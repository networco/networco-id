using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using NATS.Client.Core;
using NetworcoId.Core.Models;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;

namespace NetworcoId.Infrastructure.Auth;

public interface IKeyManagementService
{
    Task EnsureActiveKeyAsync(CancellationToken cancellationToken = default);
    Task RotateKeysAsync(CancellationToken cancellationToken = default);
    Task<List<SigningKeyEntity>> GetValidKeysAsync(CancellationToken cancellationToken = default);
}

public class KeyManagementService : IKeyManagementService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<KeyManagementService> _logger;
    private readonly INatsConnection _nats;

    // Rotation interval: 30 days
    private readonly TimeSpan _rotationInterval = TimeSpan.FromDays(30);
    
    // Grace period for previous keys: 7 days
    private readonly TimeSpan _gracePeriod = TimeSpan.FromDays(7);

    public KeyManagementService(
        IServiceProvider serviceProvider,
        ILogger<KeyManagementService> logger,
        INatsConnection nats)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _nats = nats;
    }

    public async Task EnsureActiveKeyAsync(CancellationToken cancellationToken = default)
    {
        var strategy = _serviceProvider.GetRequiredService<AuthDbContext>().Database.CreateExecutionStrategy();

        await strategy.ExecuteAsync(async () =>
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

            // Use a transaction with Serializable isolation level to prevent race conditions during initial key generation
            // This acts as a basic database-level lock for this specific operation
            using var transaction = await dbContext.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);

            try
            {
                var activeKey = await dbContext.SigningKeys
                    .Where(k => k.Status == KeyStatus.Active && !k.IsRevoked)
                    .OrderByDescending(k => k.CreatedAt)
                    .FirstOrDefaultAsync(cancellationToken);

                if (activeKey == null || (activeKey.ExpiresAt.HasValue && activeKey.ExpiresAt.Value <= DateTimeOffset.UtcNow))
                {
                    _logger.LogInformation("No active valid key found. Generating new key...");
                    await GenerateNewKeyAsync(dbContext, cancellationToken);
                    await PublishKeyRotationEventAsync();
                }

                await transaction.CommitAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error ensuring active key (possible race condition, which is handled).");
                await transaction.RollbackAsync(cancellationToken);
                // We don't rethrow here because if another pod won the race, the key exists, which is our goal.
            }
        });
    }

    public async Task RotateKeysAsync(CancellationToken cancellationToken = default)
    {
        var strategy = _serviceProvider.GetRequiredService<AuthDbContext>().Database.CreateExecutionStrategy();

        await strategy.ExecuteAsync(async () =>
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

            // 1. Check if active key needs rotation
            // We use a transaction to lock the rows involved and prevent race conditions
            using var transaction = await dbContext.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);

            try
            {
                var activeKey = await dbContext.SigningKeys
                    .Where(k => k.Status == KeyStatus.Active && !k.IsRevoked)
                    .OrderByDescending(k => k.CreatedAt)
                    .FirstOrDefaultAsync(cancellationToken);

                bool rotated = false;

                if (activeKey != null)
                {
                    // If expires soon (or already expired), rotate
                    // We rotate if < 24 hours remaining, just to be safe
                    if (activeKey.ExpiresAt.HasValue && activeKey.ExpiresAt.Value.Subtract(DateTimeOffset.UtcNow) < TimeSpan.FromHours(24))
                    {
                        _logger.LogInformation("Active key expiring soon. Rotating...");

                        // Mark current active as previous
                        activeKey.Status = KeyStatus.Previous;
                        // Extend expiration for grace period? No, ExpiresAt is for "signing usage".
                        // We keep it valid for verification as long as it's in "Previous" status.

                        await GenerateNewKeyAsync(dbContext, cancellationToken);
                        rotated = true;
                    }
                }
                else
                {
                    await GenerateNewKeyAsync(dbContext, cancellationToken);
                    rotated = true;
                }

                // 2. Retire old keys
                // If a key is Previous and older than grace period (relative to when it stopped being active), retire it.
                // Simplified logic: If created > Rotation + Grace, retire.
                var cutoff = DateTimeOffset.UtcNow.Subtract(_rotationInterval).Subtract(_gracePeriod);

                var oldKeys = await dbContext.SigningKeys
                    .Where(k => k.Status == KeyStatus.Previous && k.CreatedAt < cutoff)
                    .ToListAsync(cancellationToken);

                if (oldKeys.Any())
                {
                    foreach (var key in oldKeys)
                    {
                        key.Status = KeyStatus.Retired;
                        _logger.LogInformation("Retiring old key {KeyId}", key.KeyId);
                    }
                    // Save changes for retired keys is part of the transaction
                }

                if (rotated || oldKeys.Any())
                {
                    await dbContext.SaveChangesAsync(cancellationToken);
                    if (rotated)
                    {
                        await PublishKeyRotationEventAsync();
                    }
                }

                await transaction.CommitAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error rotating keys (possible race condition).");
                await transaction.RollbackAsync(cancellationToken);
            }
        });
    }

    private async Task PublishKeyRotationEventAsync()
    {
        try
        {
            var eventData = new { Timestamp = DateTime.UtcNow };
            var jsonBytes = global::System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(eventData);
            await _nats.PublishAsync(NetworcoIdSubjects.IdentityKeysRotated, jsonBytes);
            _logger.LogInformation("Published key rotation event to NATS.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to publish key rotation event.");
        }
    }

    private async Task GenerateNewKeyAsync(AuthDbContext dbContext, CancellationToken cancellationToken)
    {
        using var rsa = RSA.Create(2048);
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var publicKeyPem = rsa.ExportRSAPublicKeyPem();
        var keyId = Guid.NewGuid().ToString("N");

        var newKey = new SigningKeyEntity
        {
            Id = Guid.NewGuid(),
            KeyId = keyId,
            Algorithm = "RS256",
            PrivateKeyPem = privateKeyPem,
            PublicKeyPem = publicKeyPem,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.Add(_rotationInterval),
            Status = KeyStatus.Active
        };

        dbContext.SigningKeys.Add(newKey);
        await dbContext.SaveChangesAsync(cancellationToken);
        
        _logger.LogInformation("Generated new active signing key: {KeyId}", keyId);
    }


    public async Task<List<SigningKeyEntity>> GetValidKeysAsync(CancellationToken cancellationToken = default)
    {
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

        // Return Active and Previous keys
        return await dbContext.SigningKeys
            .Where(k => !k.IsRevoked && (k.Status == KeyStatus.Active || k.Status == KeyStatus.Previous))
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }
}

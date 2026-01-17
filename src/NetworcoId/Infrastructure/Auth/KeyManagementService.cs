using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
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

    // Rotation interval: 30 days
    private readonly TimeSpan _rotationInterval = TimeSpan.FromDays(30);
    
    // Grace period for previous keys: 7 days
    private readonly TimeSpan _gracePeriod = TimeSpan.FromDays(7);

    public KeyManagementService(
        IServiceProvider serviceProvider,
        ILogger<KeyManagementService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task EnsureActiveKeyAsync(CancellationToken cancellationToken = default)
    {
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

        var activeKey = await dbContext.SigningKeys
            .Where(k => k.Status == KeyStatus.Active && !k.IsRevoked)
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

        if (activeKey == null || (activeKey.ExpiresAt.HasValue && activeKey.ExpiresAt.Value <= DateTimeOffset.UtcNow))
        {
            _logger.LogInformation("No active valid key found. Generating new key...");
            await GenerateNewKeyAsync(dbContext, cancellationToken);
        }
    }

    public async Task RotateKeysAsync(CancellationToken cancellationToken = default)
    {
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

        // 1. Check if active key needs rotation
        var activeKey = await dbContext.SigningKeys
            .Where(k => k.Status == KeyStatus.Active && !k.IsRevoked)
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

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
            }
        }
        else
        {
            await GenerateNewKeyAsync(dbContext, cancellationToken);
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
            await dbContext.SaveChangesAsync(cancellationToken);
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

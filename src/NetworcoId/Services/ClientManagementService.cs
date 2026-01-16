using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;
using NetworcoId.Core.Security;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace NetworcoId.Services;

public interface IClientManagementService
{
    Task<List<OAuthClientEntity>> GetClientsAsync();
    Task<OAuthClientEntity?> GetClientAsync(string clientId);
    Task<(OAuthClientEntity Client, string Secret)> CreateClientAsync(string displayName, List<string> redirectUris, List<string> allowedScopes);
    Task UpdateClientAsync(string clientId, string displayName, List<string> redirectUris, List<string> allowedScopes);
    Task<string?> RotateClientSecretAsync(string clientId, bool isPrimary);
    Task ClearSecondarySecretAsync(string clientId);
    Task<bool> ToggleClientStatusAsync(string clientId);
    Task<bool> DeleteClientAsync(string clientId);
    Task SyncFromConfigAsync();
}

public class ClientManagementService(
    AuthDbContext dbContext,
    IPasswordHasher passwordHasher,
    NetworcoIdConfig config) : IClientManagementService
{
    public async Task<List<OAuthClientEntity>> GetClientsAsync()
    {
        return await dbContext.OAuthClients
            .OrderByDescending(c => c.CreatedAt)
            .ToListAsync();
    }

    public async Task<OAuthClientEntity?> GetClientAsync(string clientId)
    {
        return await dbContext.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
    }

    public async Task<(OAuthClientEntity Client, string Secret)> CreateClientAsync(string displayName, List<string> redirectUris, List<string> allowedScopes)
    {
        var clientId = "nw_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

        while (await dbContext.OAuthClients.AnyAsync(c => c.ClientId == clientId))
        {
            clientId = "nw_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        }

        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var secretHash = passwordHasher.HashPassword(secret);

        var client = new OAuthClientEntity
        {
            ClientId = clientId,
            PrimaryClientSecretHash = secretHash,
            DisplayName = displayName,
            RedirectUris = redirectUris,
            AllowedScopes = allowedScopes,
            CreatedAt = DateTimeOffset.UtcNow,
            IsActive = true
        };

        dbContext.OAuthClients.Add(client);
        await dbContext.SaveChangesAsync();

        return (client, secret);
    }

    public async Task UpdateClientAsync(string clientId, string displayName, List<string> redirectUris, List<string> allowedScopes)
    {
        var client = await dbContext.OAuthClients.AsTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null) return;

        client.DisplayName = displayName;
        client.RedirectUris = redirectUris;
        client.AllowedScopes = allowedScopes;
        client.UpdatedAt = DateTimeOffset.UtcNow;

        await dbContext.SaveChangesAsync();
    }

    public async Task<string?> RotateClientSecretAsync(string clientId, bool isPrimary)
    {
        var client = await dbContext.OAuthClients.AsTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null) return null;

        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var secretHash = passwordHasher.HashPassword(secret);

        if (isPrimary)
        {
            client.PrimaryClientSecretHash = secretHash;
        }
        else
        {
            client.SecondaryClientSecretHash = secretHash;
        }

        client.UpdatedAt = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync();

        return secret;
    }

    public async Task ClearSecondarySecretAsync(string clientId)
    {
        var client = await dbContext.OAuthClients.AsTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null) return;

        client.SecondaryClientSecretHash = null;
        client.UpdatedAt = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync();
    }

    public async Task<bool> ToggleClientStatusAsync(string clientId)
    {
        var client = await dbContext.OAuthClients.AsTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null) return false;

        client.IsActive = !client.IsActive;
        client.UpdatedAt = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteClientAsync(string clientId)
    {
        var client = await dbContext.OAuthClients.AsTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null) return false;

        dbContext.OAuthClients.Remove(client);
        await dbContext.SaveChangesAsync();
        return true;
    }

    public async Task SyncFromConfigAsync()
    {
        if (config.AllowedClients == null || !config.AllowedClients.Any())
        {
            return;
        }

        foreach (var clientConfig in config.AllowedClients)
        {
            var existingClient = await dbContext.OAuthClients.AsTracking()
                .FirstOrDefaultAsync(c => c.ClientId == clientConfig.ClientId);

            if (existingClient != null)
            {
                existingClient.DisplayName = clientConfig.Name;
                existingClient.RedirectUris = clientConfig.RedirectUris;
                existingClient.AllowedScopes = clientConfig.AllowedScopes;
                existingClient.UpdatedAt = DateTimeOffset.UtcNow;
                existingClient.PrimaryClientSecretHash = passwordHasher.HashPassword(clientConfig.ClientSecret);
                existingClient.SecondaryClientSecretHash = !string.IsNullOrEmpty(clientConfig.SecondaryClientSecret)
                    ? passwordHasher.HashPassword(clientConfig.SecondaryClientSecret)
                    : null;

                dbContext.OAuthClients.Update(existingClient);
            }
            else
            {
                var client = new OAuthClientEntity
                {
                    ClientId = clientConfig.ClientId,
                    DisplayName = clientConfig.Name,
                    PrimaryClientSecretHash = passwordHasher.HashPassword(clientConfig.ClientSecret),
                    SecondaryClientSecretHash = !string.IsNullOrEmpty(clientConfig.SecondaryClientSecret)
                        ? passwordHasher.HashPassword(clientConfig.SecondaryClientSecret)
                        : null,
                    RedirectUris = clientConfig.RedirectUris,
                    AllowedScopes = clientConfig.AllowedScopes,
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow
                };

                dbContext.OAuthClients.Add(client);
            }
        }

        await dbContext.SaveChangesAsync();
    }
}

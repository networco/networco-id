using Microsoft.EntityFrameworkCore;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;
using System.Security.Cryptography;

namespace NetworcoId.Services.System;

public interface IBootstrapService
{
    Task BootstrapAsync();
}

public class BootstrapService(
    AuthDbContext dbContext,
    IPasswordHasher passwordHasher,
    NetworcoIdConfig config,
    ILogger<BootstrapService> logger) : IBootstrapService
{
    public async Task BootstrapAsync()
    {
        await ProvisionSystemClientAsync();
        await ProvisionInitialAdminAsync();
    }

    private async Task ProvisionSystemClientAsync()
    {
        // Try to get existing system client ID from settings
        var systemClientIdSetting = await dbContext.SystemSettings.FirstOrDefaultAsync(s => s.Key == "System:ManagementClientId");
        var clientId = systemClientIdSetting?.Value;
        
        OAuthClientEntity? existingClient = null;
        if (!string.IsNullOrEmpty(clientId))
        {
            existingClient = await dbContext.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
        }

        if (existingClient != null)
        {
            await SyncSystemClientAsync(existingClient);
            return;
        }

        // Check if we should adopt an existing client by InitialClientId
        if (!string.IsNullOrEmpty(config.InitialClientId))
        {
            existingClient = await dbContext.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == config.InitialClientId);
            if (existingClient != null)
            {
                logger.LogInformation("Adopting existing client '{ClientId}' as the system management client.", config.InitialClientId);
                await UpdateSystemClientIdSettingAsync(config.InitialClientId);
                await SyncSystemClientAsync(existingClient);
                return;
            }
        }

        logger.LogInformation("System client not found or unconfigured. Provisioning system client...");

        // Determine Client ID
        var newClientId = config.InitialClientId;
        if (string.IsNullOrEmpty(newClientId))
        {
            newClientId = "nw_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
            while (await dbContext.OAuthClients.AnyAsync(c => c.ClientId == newClientId))
            {
                newClientId = "nw_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
            }
        }

        // Determine Client Secret
        var clientSecret = config.InitialClientSecret;
        var secretGenerated = string.IsNullOrEmpty(clientSecret);
        if (secretGenerated)
        {
            clientSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        }

        var secretHash = passwordHasher.HashPassword(clientSecret!);

        var client = new OAuthClientEntity
        {
            ClientId = newClientId,
            DisplayName = "Networco ID Management Portal",
            PrimaryClientSecretHash = secretHash,
            RedirectUris = [$"{config.BaseUrl.TrimEnd('/')}/admin/callback"],
            AllowedScopes = ["openid", "profile", "email", "address", "phone", "admin"],
            IsTrustedForExchange = true,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        dbContext.OAuthClients.Add(client);

        await UpdateSystemClientIdSettingAsync(newClientId);
        await dbContext.SaveChangesAsync();
        
        // Update runtime config
        config.SystemManagementClientId = newClientId;

        if (secretGenerated)
        {
            logger.LogCritical("********************************************************************************");
            logger.LogCritical("SYSTEM MANAGEMENT CLIENT PROVISIONED");
            logger.LogCritical("Client ID: {ClientId}", newClientId);
            logger.LogCritical("Client Secret: {ClientSecret}", clientSecret);
            logger.LogCritical("SAVE THIS SECRET SECURELY. It will not be shown again.");
            logger.LogCritical("The Admin Portal depends on these credentials.");
            logger.LogCritical("********************************************************************************");
        }
        else
        {
            logger.LogInformation("System management client '{ClientId}' provisioned with configured secret.", newClientId);
        }
    }

    private async Task SyncSystemClientAsync(OAuthClientEntity client)
    {
        var requiredScopes = new[] { "openid", "profile", "email", "address", "phone", "admin" };
        var changed = false;
        
        client.AllowedScopes ??= [];
        foreach (var scope in requiredScopes)
        {
            if (!client.AllowedScopes.Contains(scope))
            {
                client.AllowedScopes.Add(scope);
                changed = true;
            }
        }

        // Sync Redirect URIs with BaseUrl
        var expectedRedirectUri = $"{config.BaseUrl.TrimEnd('/')}/admin/callback";
        client.RedirectUris ??= [];
        if (!client.RedirectUris.Contains(expectedRedirectUri))
        {
            client.RedirectUris.Add(expectedRedirectUri);
            changed = true;
        }
        
        if (changed)
        {
            logger.LogInformation("Updated system client configuration for '{ClientId}'.", client.ClientId);
            await dbContext.SaveChangesAsync();
        }
        
        // Update runtime config
        config.SystemManagementClientId = client.ClientId;
    }

    private async Task UpdateSystemClientIdSettingAsync(string clientId)
    {
        var setting = await dbContext.SystemSettings.FirstOrDefaultAsync(s => s.Key == "System:ManagementClientId");
        if (setting == null)
        {
            dbContext.SystemSettings.Add(new SystemSettingEntity 
            { 
                Key = "System:ManagementClientId", 
                Value = clientId,
                UpdatedAt = DateTimeOffset.UtcNow
            });
        }
        else
        {
            setting.Value = clientId;
            setting.UpdatedAt = DateTimeOffset.UtcNow;
            dbContext.SystemSettings.Update(setting);
        }
    }

    private async Task ProvisionInitialAdminAsync()
    {
        var email = config.InitialAdminEmail ?? "admin@networco.local";
        var existingAdmin = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);

        if (existingAdmin != null)
        {
            // Ensure admin has the 'admin' role
            existingAdmin.Roles ??= [];
            if (!existingAdmin.Roles.Contains("admin"))
            {
                logger.LogInformation("Adding 'admin' role to existing admin user '{Email}'.", email);
                existingAdmin.Roles.Add("admin");
                await dbContext.SaveChangesAsync();
            }

            // Also check other potential admins from config or environment
            var extraAdmins = Environment.GetEnvironmentVariable("NETWORCO_EXTRA_ADMINS")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? Array.Empty<string>();
            logger.LogInformation("Found {Count} extra admins to check: {Admins}", extraAdmins.Length, string.Join(", ", extraAdmins));
            foreach (var extraEmail in extraAdmins)
            {
                var extraUser = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == extraEmail);
                if (extraUser != null)
                {
                    extraUser.Roles ??= [];
                    if (!extraUser.Roles.Contains("admin"))
                    {
                        logger.LogInformation("Adding 'admin' role to extra admin user '{Email}'.", extraEmail);
                        extraUser.Roles.Add("admin");
                        await dbContext.SaveChangesAsync();
                    }
                    else
                    {
                        logger.LogInformation("User '{Email}' already has 'admin' role.", extraEmail);
                    }
                }
                else
                {
                    logger.LogWarning("Extra admin user '{Email}' not found in database.", extraEmail);
                }
            }

            // If admin exists and we have a forced initial password, ensure it's set
            // only if they haven't changed it yet (MustChangePassword is still true)
            if (!string.IsNullOrEmpty(config.InitialAdminPassword))
            {
                var existingCredential = await dbContext.UserCredentials.FirstOrDefaultAsync(c => c.Id == existingAdmin.Id);
                if (existingCredential != null && existingCredential.MustChangePassword)
                {
                    var newHash = passwordHasher.HashPassword(config.InitialAdminPassword);
                    if (existingCredential.PasswordHash != newHash)
                    {
                        logger.LogInformation("Updating initial admin password to match configuration.");
                        existingCredential.PasswordHash = newHash;
                        await dbContext.SaveChangesAsync();
                    }
                }
            }
            return;
        }

        logger.LogInformation("No users found. Provisioning initial admin user...");

        var adminId = Guid.NewGuid();
        var password = config.InitialAdminPassword ?? ("Admin_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant());
        
        var user = new UserEntity
        {
            Id = adminId,
            Email = email,
            FirstName = "System",
            LastName = "Administrator",
            Roles = ["admin"],
            CreatedAt = DateTimeOffset.UtcNow,
            EmailVerified = true,
            IsActive = true
        };

        var credential = new UserCredentialEntity
        {
            Id = adminId,
            PasswordHash = passwordHasher.HashPassword(password),
            MustChangePassword = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        dbContext.Users.Add(user);
        dbContext.UserCredentials.Add(credential);
        await dbContext.SaveChangesAsync();

        if (string.IsNullOrEmpty(config.InitialAdminPassword))
        {
            logger.LogCritical("********************************************************************************");
            logger.LogCritical("INITIAL ADMIN USER CREATED");
            logger.LogCritical("Email: {Email}", email);
            logger.LogCritical("Temporary Password: {Password}", password);
            logger.LogCritical("Please change this password immediately after first login.");
            logger.LogCritical("********************************************************************************");
        }
        else
        {
            logger.LogInformation("Initial admin user '{Email}' provisioned using configuration password.", email);
        }
    }
}

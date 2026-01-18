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
        var clientId = config.InitialClientId ?? "networco-admin";
        var existingClient = await dbContext.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);

        if (existingClient != null)
        {
            var requiredScopes = new[] { "openid", "profile", "email", "address", "phone", "admin" };
            var changed = false;
            
            existingClient.AllowedScopes ??= new List<string>();
            foreach (var scope in requiredScopes)
            {
                if (!existingClient.AllowedScopes.Contains(scope))
                {
                    existingClient.AllowedScopes.Add(scope);
                    changed = true;
                }
            }

            // Sync Redirect URIs with BaseUrl
            var expectedRedirectUri = $"{config.BaseUrl.TrimEnd('/')}/admin/callback";
            existingClient.RedirectUris ??= new List<string>();
            if (!existingClient.RedirectUris.Contains(expectedRedirectUri))
            {
                existingClient.RedirectUris.Add(expectedRedirectUri);
                changed = true;
            }
            
            if (changed)
            {
                logger.LogInformation("Updated system client configuration for '{ClientId}'.", clientId);
                await dbContext.SaveChangesAsync();
            }
            return;
        }

        if (await dbContext.OAuthClients.AnyAsync())
        {
            return;
        }

        logger.LogInformation("First run detected: No OAuth2 clients found. Provisioning system client...");

        var clientSecret = config.InitialClientSecret ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var secretHash = passwordHasher.HashPassword(clientSecret);

        var client = new OAuthClientEntity
        {
            ClientId = clientId,
            DisplayName = "Networco ID Management Portal",
            PrimaryClientSecretHash = secretHash,
            RedirectUris = new List<string> { $"{config.BaseUrl.TrimEnd('/')}/admin/callback" },
            AllowedScopes = new List<string> { "openid", "profile", "email", "address", "phone", "admin" },
            IsTrustedForExchange = true,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        dbContext.OAuthClients.Add(client);
        await dbContext.SaveChangesAsync();

        if (string.IsNullOrEmpty(config.InitialClientSecret))
        {
            logger.LogCritical("********************************************************************************");
            logger.LogCritical("SYSTEM CLIENT PROVISIONED");
            logger.LogCritical("Client ID: {ClientId}", clientId);
            logger.LogCritical("Client Secret: {ClientSecret}", clientSecret);
            logger.LogCritical("SAVE THIS SECRET SECURELY. It will not be shown again.");
            logger.LogCritical("********************************************************************************");
        }
        else
        {
            logger.LogInformation("System client '{ClientId}' provisioned using configuration secret.", clientId);
        }
    }

    private async Task ProvisionInitialAdminAsync()
    {
        var email = config.InitialAdminEmail ?? "admin@networco.local";
        var existingAdmin = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);

        if (existingAdmin != null)
        {
            // Ensure admin has the 'admin' role
            existingAdmin.Roles ??= new List<string>();
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
                    extraUser.Roles ??= new List<string>();
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
        var password = config.InitialAdminPassword ?? ("Admin_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)));
        
        var user = new UserEntity
        {
            Id = adminId,
            Email = email,
            FirstName = "System",
            LastName = "Administrator",
            Roles = new List<string> { "admin" },
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

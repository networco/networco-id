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
        if (await dbContext.OAuthClients.AnyAsync())
        {
            return;
        }

        logger.LogInformation("First run detected: No OAuth2 clients found. Provisioning system client...");

        var clientId = config.InitialClientId ?? "networco-admin";
        var clientSecret = config.InitialClientSecret ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var secretHash = passwordHasher.HashPassword(clientSecret);

        var client = new OAuthClientEntity
        {
            ClientId = clientId,
            DisplayName = "Networco ID Management Portal",
            PrimaryClientSecretHash = secretHash,
            RedirectUris = new List<string> { $"{config.BaseUrl.TrimEnd('/')}/admin/callback" },
            AllowedScopes = new List<string> { "openid", "profile", "email", "admin" },
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
        if (await dbContext.Users.AnyAsync())
        {
            return;
        }

        logger.LogInformation("No users found. Provisioning initial admin user...");

        var adminId = Guid.NewGuid();
        var email = config.InitialAdminEmail ?? "admin@networco.local";
        var password = config.InitialAdminPassword ?? ("Admin_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)));
        
        var user = new UserEntity
        {
            Id = adminId,
            Email = email,
            FirstName = "System",
            LastName = "Administrator",
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

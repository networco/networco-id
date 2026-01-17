using NetworcoId.Core.Security;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using NetworcoId.Services.System;
using NetworcoId.Services.Audit;
using NetworcoId.Infrastructure.Auth;
using NetworcoId.Workers;

using Microsoft.Extensions.Options;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;

namespace NetworcoId.Configuration;

/// <summary>
/// Service configuration and dependency injection.
/// </summary>
public static class ServiceConfiguration
{
    /// <summary>
    /// Adds authentication services to the DI container.
    /// </summary>
    public static IServiceCollection AddAuthServices(this IServiceCollection services, IConfiguration configuration)
    {
        // Infrastructure services
        services.AddSingleton<IPasswordHasher, PasswordHasher>();
        services.AddSingleton<IPasswordValidator, PasswordValidator>();
        
        // Add Memory Cache for JWKS caching
        services.AddMemoryCache();

        // Configuration
        services.Configure<NetworcoIdConfig>(configuration.GetSection("NetworcoId"));
        services.AddSingleton(provider =>
        {
            var config = provider.GetRequiredService<IOptions<NetworcoIdConfig>>().Value;
            
            // Fallback for signing key - check Auth:Jwt:SigningKey which is standard for API
            if (string.IsNullOrEmpty(config.Secret))
            {
                config.Secret = configuration["Auth:Jwt:SigningKey"] 
                             ?? configuration["JWT_SECRET"];
            }

            // Fallbacks for bootstrap configuration from environment variables
            config.InitialAdminEmail ??= configuration["INITIAL_ADMIN_EMAIL"];
            config.InitialAdminPassword ??= configuration["INITIAL_ADMIN_PASSWORD"];
            config.InitialClientId ??= configuration["INITIAL_CLIENT_ID"];
            config.InitialClientSecret ??= configuration["INITIAL_CLIENT_SECRET"];
            
            // Data Protection Config
            config.DataProtectionCertificatePath ??= configuration["DATA_PROTECTION_CERT_PATH"];
            config.DataProtectionCertificatePassword ??= configuration["DATA_PROTECTION_CERT_PASSWORD"];

            return config;
        });

        // Key management
        services.AddScoped<IKeyManagementService, KeyManagementService>();
        services.AddHostedService<KeyRotationWorker>();
        services.AddHostedService<CacheInvalidationWorker>();

        // JWT service
        services.AddScoped<IJwtService, JwtService>();

        // Business services
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IAuthSeeder, AuthSeeder>();
        services.AddScoped<IBootstrapService, BootstrapService>();
        services.AddScoped<IClientManagementService, ClientManagementService>();
        services.AddScoped<Services.Messaging.IEmailService, Services.Messaging.NatsEmailService>();

        return services;
    }
}

/// <summary>
/// JSON serialization configuration.
/// </summary>
public static class JsonConfiguration
{
    /// <summary>
    /// Adds JSON serialization with custom options.
    /// </summary>
    public static IServiceCollection AddJsonSerialization(this IServiceCollection services)
    {
        services.ConfigureHttpJsonOptions(options =>
        {
            options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
        });

        return services;
    }
}

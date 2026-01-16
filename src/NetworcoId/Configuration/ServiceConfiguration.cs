using NetworcoId.Core.Security;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using NetworcoId.Services.System;
using NetworcoId.Services.Audit;

using Microsoft.Extensions.Options;
using System.Text.Json;
using System.Text.Json.Serialization;

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
            
            return config;
        });

        // JWT service
        services.AddSingleton<Infrastructure.Auth.IJwtService, Infrastructure.Auth.JwtService>();

        // Business services
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IAuthSeeder, AuthSeeder>();
        services.AddScoped<IBootstrapService, BootstrapService>();
        services.AddScoped<IClientManagementService, ClientManagementService>();

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
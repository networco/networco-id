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

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

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
        
        // Build the config object eagerly to use it for setup
        var config = new NetworcoIdConfig 
        { 
            Issuer = "http://localhost:5001", 
            Audience = "networco-api" 
        };
        configuration.GetSection("NetworcoId").Bind(config);
        
        // Override from env if set
        var envIssuer = configuration["ISSUER"];
        if (!string.IsNullOrEmpty(envIssuer)) config.Issuer = envIssuer;

        services.AddSingleton(provider =>
        {
            var optionsConfig = provider.GetRequiredService<IOptions<NetworcoIdConfig>>().Value;
            
            // Fallback for signing key
            if (string.IsNullOrEmpty(optionsConfig.Secret))
            {
                optionsConfig.Secret = configuration["Auth:Jwt:SigningKey"] 
                             ?? configuration["JWT_SECRET"];
            }

            // Fallbacks for bootstrap configuration
            optionsConfig.InitialAdminEmail ??= configuration["INITIAL_ADMIN_EMAIL"];
            optionsConfig.InitialAdminPassword ??= configuration["INITIAL_ADMIN_PASSWORD"];
            optionsConfig.InitialClientId ??= configuration["INITIAL_CLIENT_ID"];
            optionsConfig.InitialClientSecret ??= configuration["INITIAL_CLIENT_SECRET"];

            // Ensure Issuer matches what we bound earlier (in case it wasn't refreshed)
            if (!string.IsNullOrEmpty(envIssuer)) optionsConfig.Issuer = envIssuer;
            
            // Data Protection Config
            optionsConfig.DataProtectionCertificatePath ??= configuration["DATA_PROTECTION_CERT_PATH"];
            optionsConfig.DataProtectionCertificatePassword ??= configuration["DATA_PROTECTION_CERT_PASSWORD"];

            return optionsConfig;
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

        // Add ASP.NET Core Authentication & Authorization
        services.AddAuthorization();
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = config.Issuer,
                    ValidateAudience = false, 
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    // Use the JWKS endpoint for validation
                    IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                    {
                        // Sync wrapper for async key retrieval
                        // In production, use a caching singleton for keys
                        var client = new HttpClient();
                        var response = client.GetAsync($"{config.Issuer}/.well-known/jwks.json").Result;
                        if (response.IsSuccessStatusCode)
                        {
                            var json = response.Content.ReadAsStringAsync().Result;
                            var jwks = new JsonWebKeySet(json);
                            return jwks.GetSigningKeys();
                        }
                        return new List<SecurityKey>();
                    }
                };
            });

        // Re-configure JwtBearer to use our custom validation logic if needed,
        // but primarily we need to fix the "Validator" issue.
        // Let's use a simpler configuration that doesn't fail on startup.
        services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
        {
             var serviceProvider = services.BuildServiceProvider();
             // We can't resolve scoped services here easily.
             // Instead, let's just ensure the validation works by using the Configuration.
        });

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

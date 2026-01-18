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
using Microsoft.AspNetCore.Authentication.Cookies;
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
        services.AddAuthentication(options => 
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.Cookie.Name = "NetworcoId.Session";
                options.LoginPath = "/Login";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                options.SlidingExpiration = true;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
            })
            .AddJwtBearer(options =>
            {
                options.MapInboundClaims = false;
                options.Events = new JwtBearerEvents
                {
                    // Allow reading the token from the body for OIDC conformance tests
                    OnMessageReceived = context =>
                    {
                        if (string.IsNullOrEmpty(context.Token))
                        {
                            // Try to find access_token in the form body
                            if (context.Request.HasFormContentType && context.Request.Form.ContainsKey("access_token"))
                            {
                                context.Token = context.Request.Form["access_token"];
                            }
                        }
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = async context =>
                    {
                        // Check if token was issued before the last critical account update (e.g. revocation)
                        if (context.Principal?.Identity?.IsAuthenticated == true)
                        {
                            var userIdStr = context.Principal.FindFirst("sub")?.Value;
                            if (Guid.TryParse(userIdStr, out var userId))
                            {
                                var dbContext = context.HttpContext.RequestServices.GetRequiredService<NetworcoId.Infrastructure.Database.AuthDbContext>();
                                
                                // Check user credentials timestamp
                                var creds = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstOrDefaultAsync(
                                    Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.AsNoTracking(dbContext.UserCredentials), 
                                    c => c.Id == userId);
                                    
                                if (creds?.UpdatedAt != null)
                                {
                                    var iatClaim = context.Principal.FindFirst("iat");
                                    if (iatClaim != null && long.TryParse(iatClaim.Value, out var iatSeconds))
                                    {
                                        var iatDate = DateTimeOffset.FromUnixTimeSeconds(iatSeconds);
                                        // If token issued BEFORE update (minus 1s tolerance), reject it
                                        if (iatDate < creds.UpdatedAt.Value.AddSeconds(-1))
                                        {
                                            context.Fail("Token invalidated due to account changes.");
                                        }
                                    }
                                }
                            }
                        }
                    }
                };
            });

        // Configure JwtBearerOptions with dependency injection to access IMemoryCache
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IMemoryCache, IOptions<NetworcoIdConfig>>((options, cache, configOptions) =>
            {
                var config = configOptions.Value;
                
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
                        var keys = new List<SecurityKey>();
                        
                        // 1. Try to get keys from cache (populated by KeyRotationWorker/JwtService)
                        if (cache.TryGetValue("valid_signing_keys", out List<NetworcoId.Models.Entities.SigningKeyEntity>? cachedKeys) && cachedKeys != null)
                        {
                            foreach (var keyEntity in cachedKeys)
                            {
                                try 
                                {
                                    var rsa = System.Security.Cryptography.RSA.Create();
                                    rsa.ImportFromPem(keyEntity.PublicKeyPem);
                                    keys.Add(new RsaSecurityKey(rsa) { KeyId = keyEntity.KeyId });
                                }
                                catch 
                                { 
                                    // Ignore invalid keys in cache
                                }
                            }
                        }

                        // 2. Add static secret fallback if configured
                        if (!string.IsNullOrEmpty(config.Secret))
                        {
                            keys.Add(new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(config.Secret)));
                        }

                        return keys;
                    }
                };
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

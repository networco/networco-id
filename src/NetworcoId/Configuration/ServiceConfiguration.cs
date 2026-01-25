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
        // Priority: Environment Variable (ISSUER) > appsettings.json > Default
        var issuer = configuration["ISSUER"]
                    ?? configuration["NetworcoId:Issuer"]
                    ?? "http://localhost:5001";

        var baseUrl = configuration["BASE_URL"]
                    ?? configuration["NetworcoId:BaseUrl"]
                    ?? "http://localhost:5200";

        var config = new NetworcoIdConfig
        {
            Issuer = issuer,
            Audience = configuration["JWT_AUDIENCE"] ?? "networco-api",
            BaseUrl = baseUrl
        };
        configuration.GetSection("NetworcoId").Bind(config);

        // Ensure values are set correctly after binding (if not overridden by env)
        config.Issuer = issuer;
        config.BaseUrl = baseUrl;

        services.AddSingleton(provider =>
        {
            var optionsConfig = provider.GetRequiredService<IOptions<NetworcoIdConfig>>().Value;

            // Re-apply to options to be safe
            optionsConfig.Issuer = issuer;
            optionsConfig.BaseUrl = baseUrl;

            // Fallback for signing key
            if (string.IsNullOrEmpty(optionsConfig.Secret))
            {
                optionsConfig.Secret = configuration["Auth:Jwt:SigningKey"]
                             ?? configuration["JWT_SECRET"];
            }

            // Fallbacks for bootstrap configuration
            optionsConfig.InitialAdminEmail ??= configuration["INITIAL_ADMIN_EMAIL"];
            optionsConfig.InitialAdminPassword ??= configuration["INITIAL_ADMIN_PASSWORD"] ?? configuration["Admin:Password"];
            optionsConfig.InitialClientId ??= configuration["INITIAL_CLIENT_ID"];
            optionsConfig.InitialClientSecret ??= configuration["INITIAL_CLIENT_SECRET"];

            // Data Protection Config
            optionsConfig.DataProtectionCertificatePath ??= configuration["DATA_PROTECTION_CERT_PATH"];
            optionsConfig.DataProtectionCertificatePassword ??= configuration["DATA_PROTECTION_CERT_PASSWORD"];

            return optionsConfig;
        });

        // Key management
        services.AddScoped<IKeyManagementService, KeyManagementService>();
        services.AddHostedService<KeyRotationWorker>();
        services.AddHostedService<CacheInvalidationWorker>();
        services.AddHostedService<LockoutCleanupWorker>();

        // JWT service
        services.AddScoped<IJwtService, JwtService>();

        // Business services
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IAuthSeeder, AuthSeeder>();
        services.AddScoped<IBootstrapService, BootstrapService>();
        services.AddSingleton<ISettingsService, SettingsService>();
        services.AddHostedService<SettingsInitialLoader>();
        services.AddScoped<IClientManagementService, ClientManagementService>();
        services.AddScoped<Services.Messaging.IEmailService, Services.Messaging.NatsEmailService>();
        services.AddScoped<Services.Security.ILockoutService, Services.Security.LockoutService>();

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
                    ValidateAudience = true,
                    // Allow both the global audience and dynamic audiences from the database
                    ValidAudience = config.Audience,
                    AudienceValidator = (audiences, securityToken, validationParameters) =>
                    {
                        if (audiences == null || !audiences.Any()) return false;
                        
                        // 1. Check if it matches the primary audience (IDP itself)
                        if (audiences.Contains(config.Audience)) return true;
                        
                        // 2. Check if it's a registered client audience
                        // We use a scope here to access the database
                        using var scope = services.BuildServiceProvider().CreateScope();
                        var dbContext = scope.ServiceProvider.GetRequiredService<NetworcoId.Infrastructure.Database.AuthDbContext>();
                        
                        return audiences.Any(aud => dbContext.OAuthClients.Any(c => c.Audience == aud));
                    },
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

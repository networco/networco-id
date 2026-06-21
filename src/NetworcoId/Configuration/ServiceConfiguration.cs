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

        var frontendUrl = configuration["FRONTEND_URL"]
                    ?? configuration["NetworcoId:FrontendUrl"]
                    ?? "http://localhost:3000";

        var config = new NetworcoIdConfig
        {
            Issuer = issuer,
            Audience = configuration["JWT_AUDIENCE"] ?? "networco-api",
            BaseUrl = baseUrl,
            FrontendUrl = frontendUrl
        };
        configuration.GetSection("NetworcoId").Bind(config);

        // Ensure values are set correctly after binding (if not overridden by env)
        config.Issuer = issuer;
        config.BaseUrl = baseUrl;
        config.FrontendUrl = frontendUrl;

        // External login (IDura / BankID). Read process env vars FIRST — .env is
        // loaded by DotNetEnv after WebApplicationBuilder snapshots its env-var
        // configuration provider, so configuration["IDURA_*"] would miss .env
        // values. This mirrors how DATABASE_URL/NATS_URL are read in Program.cs.
        static string? EnvOr(IConfiguration cfg, string envKey, string cfgKey)
            => Environment.GetEnvironmentVariable(envKey) ?? cfg[envKey] ?? cfg[cfgKey];

        var iduraDomain = EnvOr(configuration, "IDURA_DOMAIN", "NetworcoId:IduraDomain");
        var iduraClientId = EnvOr(configuration, "IDURA_CLIENT_ID", "NetworcoId:IduraClientId");
        var iduraClientSecret = EnvOr(configuration, "IDURA_CLIENT_SECRET", "NetworcoId:IduraClientSecret");
        // No `email` scope on purpose: for Norwegian BankID the email is "contact
        // information" that Vipps/BankID makes the user re-consent to on EVERY login (an
        // unavoidable, operator-rendered dialog). We don't need it from BankID — users
        // provide/verify their own email in-app — so we omit it to skip that prompt.
        // `birthdate` comes from the certificate and triggers no consent.
        var iduraScopes = EnvOr(configuration, "IDURA_SCOPES", "NetworcoId:IduraScopes") ?? "openid birthdate";
        var iduraCallbackPath = EnvOr(configuration, "IDURA_CALLBACK_PATH", "NetworcoId:IduraCallbackPath") ?? "/auth/callback/external";
        var iduraAcrValues = EnvOr(configuration, "IDURA_ACR_VALUES", "NetworcoId:IduraAcrValues");
        // Only enable when explicitly turned on AND fully configured — otherwise the
        // OIDC scheme (which needs a reachable authority) isn't registered at all.
        var iduraEnabledRaw = Environment.GetEnvironmentVariable("IDURA_ENABLED") ?? configuration["IDURA_ENABLED"];
        var iduraEnabled = (string.Equals(iduraEnabledRaw, "true", StringComparison.OrdinalIgnoreCase)
                || configuration.GetValue<bool>("NetworcoId:IduraEnabled"))
            && !string.IsNullOrWhiteSpace(iduraDomain)
            && !string.IsNullOrWhiteSpace(iduraClientId)
            && !string.IsNullOrWhiteSpace(iduraClientSecret);

        config.IduraEnabled = iduraEnabled;
        config.IduraDomain = iduraDomain;
        config.IduraClientId = iduraClientId;
        config.IduraClientSecret = iduraClientSecret;
        config.IduraScopes = iduraScopes;
        config.IduraCallbackPath = iduraCallbackPath;
        config.IduraAcrValues = iduraAcrValues;

        services.AddSingleton(provider =>
        {
            var optionsConfig = provider.GetRequiredService<IOptions<NetworcoIdConfig>>().Value;

            // Re-apply to options to be safe
            optionsConfig.Issuer = issuer;
            optionsConfig.BaseUrl = baseUrl;
            optionsConfig.FrontendUrl = frontendUrl;

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

            // External login (IDura / BankID) — mirror onto the runtime options object
            // so pages/endpoints (e.g. the BankID button gate) can read it.
            optionsConfig.IduraEnabled = iduraEnabled;
            optionsConfig.IduraDomain = iduraDomain;
            optionsConfig.IduraClientId = iduraClientId;
            optionsConfig.IduraClientSecret = iduraClientSecret;
            optionsConfig.IduraScopes = iduraScopes;
            optionsConfig.IduraCallbackPath = iduraCallbackPath;
            optionsConfig.IduraAcrValues = iduraAcrValues;

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
        // OAuth authorization-code store backed by NATS KV — survives pod
        // restarts, replicates with NATS, TTL'd to match the 5-minute code
        // lifetime. Singleton so the lazily-initialised KV bucket handle is
        // shared across requests.
        services.AddSingleton<IAuthCodeStore, NatsKvAuthCodeStore>();
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
        var authBuilder = services.AddAuthentication(options =>
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

        // External login via IDura (BankID broker). Registered only when fully
        // configured so the app still boots without IDura credentials (and tests,
        // which never set them, are unaffected).
        if (iduraEnabled)
        {
            authBuilder
                // Short-lived first-party cookie that holds the external identity
                // between the OIDC callback and our /auth/external/complete handler.
                .AddCookie("ExternalLogin", options =>
                {
                    options.Cookie.Name = "NetworcoId.External";
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.Lax;
                })
                .AddOpenIdConnect("idura", options =>
                {
                    options.Authority = $"https://{iduraDomain!.Trim().TrimEnd('/')}/";
                    options.ClientId = iduraClientId;
                    options.ClientSecret = iduraClientSecret;
                    options.ResponseType = "code";
                    options.UsePkce = true;
                    options.CallbackPath = iduraCallbackPath;
                    options.SignInScheme = "ExternalLogin";
                    options.SaveTokens = false;
                    // IDura returns the identity claims inside the ID token (its default
                    // "fromTokenEndpoint" strategy), so we must NOT call the UserInfo
                    // endpoint — doing so returns 400. Read claims from the ID token.
                    options.GetClaimsFromUserInfoEndpoint = false;
                    options.MapInboundClaims = false;

                    options.Scope.Clear();
                    foreach (var s in iduraScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    {
                        options.Scope.Add(s);
                    }

                    options.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
                    {
                        OnRedirectToIdentityProvider = ctx =>
                        {
                            if (!string.IsNullOrWhiteSpace(iduraAcrValues))
                            {
                                ctx.ProtocolMessage.AcrValues = iduraAcrValues;
                            }
                            return Task.CompletedTask;
                        },
                        OnRemoteFailure = ctx =>
                        {
                            ctx.Response.Redirect("/Login?error=external&error_description="
                                + Uri.EscapeDataString("BankID-pålogging mislyktes. Prøv igjen."));
                            ctx.HandleResponse();
                            return Task.CompletedTask;
                        }
                    };
                });
        }

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

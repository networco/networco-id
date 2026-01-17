using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Caching.Memory;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using Xunit;
using NetworcoId.Infrastructure.Auth;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace NetworcoId.Tests.Integration;

public class JwksRotationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public JwksRotationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            // Try to signal to DatabaseConfiguration to skip Npgsql registration
            builder.UseSetting("ConnectionStrings:DefaultConnection", "InMemory");
            builder.UseSetting("NetworcoId:Nats:ProvisionStreams", "false");

            builder.ConfigureServices(services =>
            {
                // Aggressively remove existing database services
                var dbContextOptions = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>));
                if (dbContextOptions != null) services.Remove(dbContextOptions);

                var dbContextOptionsGeneric = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions));
                if (dbContextOptionsGeneric != null) services.Remove(dbContextOptionsGeneric);

                var dbContext = services.SingleOrDefault(d => d.ServiceType == typeof(AuthDbContext));
                if (dbContext != null) services.Remove(dbContext);

                // Add InMemory DbContext
                // Use a unique name to ensure isolation
                var dbName = "InMemoryDbForTesting_JwksRotation_" + Guid.NewGuid();
                services.AddDbContext<AuthDbContext>(options =>
                {
                    options.UseInMemoryDatabase(dbName);
                    options.EnableSensitiveDataLogging(); 
                });

                // Ensure JwtService uses the correct context (re-register key manager to be safe)
                var keyManagerDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IKeyManagementService));
                if (keyManagerDescriptor != null) services.Remove(keyManagerDescriptor);
                
                services.AddScoped<IKeyManagementService, KeyManagementService>();
            });
        });
    }

    [Fact]
    public async Task JwksEndpoint_ReturnsKeys_WhenKeysExist()
    {
        // Arrange
        var client = _factory.CreateClient();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var keyManager = scope.ServiceProvider.GetRequiredService<IKeyManagementService>();
            
            // Force create keys
            await keyManager.RotateKeysAsync();
        }

        // Act
        var response = await client.GetAsync("/.well-known/jwks.json");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        response.EnsureSuccessStatusCode();
        Assert.Contains("keys", content);
        Assert.Contains("kid", content);
    }

    [Fact]
    public async Task TokenSignedByOldKey_StillValidates()
    {
        // Arrange
        var client = _factory.CreateClient();
        string oldToken;
        
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var keyManager = scope.ServiceProvider.GetRequiredService<IKeyManagementService>();
            var jwtService = scope.ServiceProvider.GetRequiredService<IJwtService>();

            // Generate initial keys
            await keyManager.RotateKeysAsync();
            
            // Get the current active key to sign manually (simulating "old" key later)
            var activeKey = await db.SigningKeys.FirstAsync(k => k.Status == KeyStatus.Active);
            
            // Create a token manually with this key
            var rsa = RSA.Create();
            rsa.ImportFromPem(activeKey.PrivateKeyPem);
            var securityKey = new RsaSecurityKey(rsa) { KeyId = activeKey.KeyId };
            var creds = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
            
            // NOTE: Must match what ValidationParameters expects (from config)
            var token = new JwtSecurityToken(
                issuer: "networco-auth-dev", // Config default
                audience: "networco-dev",    // Config default
                claims: new[] { new System.Security.Claims.Claim("sub", "test-user") },
                expires: DateTime.UtcNow.AddMinutes(5),
                signingCredentials: creds
            );
            oldToken = new JwtSecurityTokenHandler().WriteToken(token);

            // Clear cache so the service picks up the changes
            var cache = scope.ServiceProvider.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>();
            if (cache is MemoryCache memoryCache)
            {
                memoryCache.Compact(1.0); // Not ideal way to clear specific key, but simple
            }
            // Better: use reflection or just assume cache duration allows tests (10 mins)
            // But we are manually updating DB, cache won't know unless we invalidate it.
            // Wait! JwtService caches keys for 10 minutes.
            // If we update DB behind its back, it still has the old key status in cache.
            // We need to clear the cache or wait.
            // Since we can't easily clear the private cache key of another scope, 
            // we should rely on the fact that the *new* scope in Act will read from DB fresh?
            // Ah, IMemoryCache is typically Singleton if added via AddMemoryCache(), 
            // but let's check ServiceConfiguration.
            // yes: services.AddMemoryCache(); -> Singleton.
            // So the cache persists across scopes in the same factory/app instance.
            
            // We need to remove the cache entry "valid_signing_keys"
            cache.Remove("valid_signing_keys");

            // Now Rotate Keys -> Old Active becomes "Retired" (but valid)
            // Force expiration of current active key to trigger rotation logic if we were using time-based,
            // but here we just force a new rotation which should retire the old one.
            // Note: KeyManagementService logic needs to be checked if it allows immediate rotation.
            // Assuming RotateKeysAsync does the job of managing states.
            
            // Manually set status to Previous (not Retired, as Retired keys are skipped in validation)
            activeKey.Status = KeyStatus.Previous;
            activeKey.ExpiresAt = DateTime.UtcNow.AddHours(1); // Still valid for validation
            await db.SaveChangesAsync();
            
            // Create NEW active key
             await keyManager.EnsureActiveKeyAsync();
        }

        // Act - Validate using the endpoint or service
        // Since we don't have a direct "validate token" endpoint for generic tokens exposed publicly (introspection is usually for clients),
        // we'll use the service directly to verify the logic.
        using (var scope = _factory.Services.CreateScope())
        {
             var jwtService = scope.ServiceProvider.GetRequiredService<IJwtService>();
             var principal = await jwtService.ValidateTokenAsync(oldToken);
             
             // Assert
             Assert.NotNull(principal);
        }
    }
}

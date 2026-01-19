using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services;
using Xunit;

using Microsoft.Extensions.DependencyInjection.Extensions;

namespace NetworcoId.Tests.Integration;

public class PasswordUpgradeTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string? _originalDbUrl;
    
    private const string TestEmail = "upgrade.test@networco.dev";
    private const string TestPassword = "LegacyPassword123!";

    public PasswordUpgradeTests(WebApplicationFactory<Program> factory)
    {
        // 1. Force the Environment Variable BEFORE WebApplicationFactory builds the host.
        // This is critical because Program.cs reads Environment.GetEnvironmentVariable("DATABASE_URL")
        // at the very beginning of its execution.
        _originalDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
        Environment.SetEnvironmentVariable("DATABASE_URL", "InMemory");

        // Use a unique database name to ensure isolation
        var dbName = "PasswordUpgradeTestDb_" + Guid.NewGuid();

        _factory = factory.WithWebHostBuilder(builder =>
        {
            // Note: builder.UseSetting() sets IConfiguration values, but Program.cs reads the ENV VAR directly first.
            // That's why we need the Environment.SetEnvironmentVariable above.
            builder.UseSetting("ConnectionStrings:DefaultConnection", "InMemory");
            builder.UseSetting("Nats:ProvisionStreams", "false");

            builder.ConfigureServices(services =>
            {
                // Cleanly remove existing database services.
                services.RemoveAll<DbContextOptions<AuthDbContext>>();
                services.RemoveAll<DbContextOptions>();
                services.RemoveAll<AuthDbContext>();
                services.RemoveAll<IDbContextFactory<AuthDbContext>>();

                // Shared configuration for consistency
                Action<DbContextOptionsBuilder> configureOptions = options =>
                {
                    options.UseInMemoryDatabase(dbName);
                    options.ConfigureWarnings(x => x.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning));
                };

                // Register Factory as Singleton (consistent with production)
                services.AddDbContextFactory<AuthDbContext>(configureOptions, ServiceLifetime.Singleton);

                // Register Scoped DbContext using Singleton options (consistent with production)
                services.AddDbContext<AuthDbContext>(configureOptions, ServiceLifetime.Scoped, ServiceLifetime.Singleton);
            });
        });

        SeedLegacyUser();
    }
    
    public void Dispose()
    {
        // Restore original env var so we don't pollute other tests
        if (_originalDbUrl != null)
        {
            Environment.SetEnvironmentVariable("DATABASE_URL", _originalDbUrl);
        }
        else
        {
            Environment.SetEnvironmentVariable("DATABASE_URL", null);
        }
    }

    private void SeedLegacyUser()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        
        if (!db.Users.Any(u => u.Email == TestEmail))
        {
            var userId = Guid.NewGuid();
            var user = new UserEntity
            {
                Id = userId,
                Email = TestEmail,
                FirstName = "Upgrade",
                LastName = "Tester",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                NationalId = "00000000000",
                PhoneNumber = "+4700000000"
            };
            
            var legacyHash = CreateLegacyHash(TestPassword);

            var cred = new UserCredentialEntity
            {
                Id = userId,
                PasswordHash = legacyHash,
                CreatedAt = DateTimeOffset.UtcNow
            };
            
            user.Credential = cred;
            cred.User = user;

            db.Users.Add(user);
            db.UserCredentials.Add(cred);
            
            db.SaveChanges();
        }
    }
    
    private string CreateLegacyHash(string password)
    {
        // Simulate legacy PBKDF2 hash generation
        const int SaltSize = 16;
        const int HashSize = 32;
        const int Iterations = 100_000;

        byte[] salt = new byte[SaltSize];
        new Random().NextBytes(salt);
        
        byte[] hash = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: Iterations,
            numBytesRequested: HashSize);
        
        byte[] combined = new byte[SaltSize + HashSize];
        Buffer.BlockCopy(salt, 0, combined, 0, SaltSize);
        Buffer.BlockCopy(hash, 0, combined, SaltSize, HashSize);
        
        return Convert.ToBase64String(combined);
    }

    [Fact]
    public async Task AuthenticateUser_ShouldUpgradePasswordHash_FromPbkdf2_ToArgon2id()
    {
        // 1. Verify initial state is LEGACY
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var user = await db.Users
                .AsNoTracking()
                .Include(u => u.Credential)
                .FirstOrDefaultAsync(u => u.Email == TestEmail);
                
            Assert.NotNull(user);
            Assert.NotNull(user!.Credential);
            Assert.False(user.Credential.PasswordHash.StartsWith("$argon2"), "Initial hash should NOT be Argon2id");
        }

        // 2. Perform Login via AuthService directly
        using (var scope = _factory.Services.CreateScope())
        {
            var authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
            var userDto = await authService.AuthenticateUserAsync(TestEmail, TestPassword);
            
            Assert.NotNull(userDto);
            Assert.Equal(TestEmail, userDto.Email);
        }
        
        // 3. Verify final state is ARGON2ID
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var user = await db.Users
                .AsNoTracking()
                .Include(u => u.Credential)
                .FirstOrDefaultAsync(u => u.Email == TestEmail);
            
            Assert.NotNull(user);
            Assert.NotNull(user!.Credential);
            Assert.StartsWith("$argon2", user.Credential.PasswordHash);
            
            // Verify verification still works with new hash
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            Assert.True(hasher.VerifyPassword(TestPassword, user.Credential.PasswordHash), "New hash should be valid for the same password");
        }
    }
}

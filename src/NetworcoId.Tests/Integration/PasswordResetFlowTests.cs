using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services;
using NetworcoId.Services.Messaging;
using NetworcoId.Services.System;
using NATS.Client.Core;
using Moq;
using Xunit;

namespace NetworcoId.Tests.Integration;

/// <summary>
/// Regression tests for the password-reset token flow. The key guarantee:
/// completing a reset only ever clears the token on success, and an account
/// that has no local password yet (e.g. created via BankID/Vipps external
/// login) can set one through a reset instead of being told the link is invalid.
/// </summary>
public abstract class PasswordResetTestFactory : WebApplicationFactory<Program>
{
    /// <summary>When true, the password validator is mocked to accept anything;
    /// when false the real validator is used so bad passwords genuinely fail.</summary>
    protected abstract bool StubValidatorAccepts { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "ConnectionStrings:DefaultConnection", "InMemory" },
                { "Nats:ProvisionStreams", "false" },
            });
        });

        builder.ConfigureServices(services =>
        {
            var efDescriptors = services.Where(d =>
                d.ServiceType == typeof(DbContextOptions<AuthDbContext>) ||
                d.ServiceType == typeof(AuthDbContext) ||
                d.ServiceType.FullName?.Contains("Microsoft.EntityFrameworkCore") == true ||
                d.ServiceType.FullName?.Contains("Npgsql") == true ||
                d.ServiceType.FullName?.Contains("DataProtection") == true).ToList();
            foreach (var d in efDescriptors) services.Remove(d);

            var natsDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(INatsConnection));
            if (natsDescriptor != null) services.Remove(natsDescriptor);

            // Unique in-memory store per factory so the two test classes don't share data.
            var dbName = "ResetTestDb-" + (StubValidatorAccepts ? "stub" : "real");
            services.AddDbContext<AuthDbContext>(options => options.UseInMemoryDatabase(dbName));

            var mockNats = new Mock<INatsConnection>();
            mockNats.Setup(n => n.Opts).Returns(new NatsOpts());
            services.AddSingleton<INatsConnection>(mockNats.Object);

            // No outbound email in tests.
            var mockEmail = new Mock<IEmailService>();
            services.AddSingleton<IEmailService>(mockEmail.Object);

            var bootstrap = services.SingleOrDefault(d => d.ServiceType == typeof(IBootstrapService));
            if (bootstrap != null) services.Remove(bootstrap);
            services.AddScoped<IBootstrapService, NoopBootstrap>();

            services.AddDataProtection();

            if (StubValidatorAccepts)
            {
                var mockValidator = new Mock<IPasswordValidator>();
                mockValidator.Setup(v => v.Validate(
                        It.IsAny<string>(), It.IsAny<int>(), It.IsAny<bool>(),
                        It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<bool>()))
                    .Returns((true, null));
                services.AddSingleton<IPasswordValidator>(mockValidator.Object);
            }
            // else: keep the app's real validator so a short password fails.
        });
    }

    private sealed class NoopBootstrap : IBootstrapService
    {
        public Task BootstrapAsync() => Task.CompletedTask;
    }
}

public sealed class PasswordResetAcceptingFactory : PasswordResetTestFactory
{
    protected override bool StubValidatorAccepts => true;
}

public sealed class PasswordResetRealValidatorFactory : PasswordResetTestFactory
{
    protected override bool StubValidatorAccepts => false;
}

public class PasswordResetFlowTests : IClassFixture<PasswordResetAcceptingFactory>
{
    private readonly PasswordResetAcceptingFactory _factory;
    public PasswordResetFlowTests(PasswordResetAcceptingFactory factory) => _factory = factory;

    [Fact]
    public async Task Reset_PasswordlessAccount_CreatesCredentialAndClearsToken()
    {
        // Arrange — a BankID/external-login account: a valid reset token but NO credential row.
        var userId = Guid.NewGuid();
        const string token = "passwordless-token-1";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            db.Users.Add(new UserEntity
            {
                Id = userId,
                Email = "bankid@example.com",
                FirstName = "Bank",
                LastName = "Id",
                IsActive = true,
                EmailVerified = false,
                PasswordResetToken = token,
                PasswordResetTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            });
            await db.SaveChangesAsync();
        }

        // Act
        bool result;
        using (var scope = _factory.Services.CreateScope())
        {
            var auth = scope.ServiceProvider.GetRequiredService<IAuthService>();
            result = await auth.ResetPasswordWithTokenAsync(token, "BrandNewP@ss123!");
        }

        // Assert — credential created with the new password, token cleared, email auto-verified.
        Assert.True(result);
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            var cred = await db.UserCredentials.AsNoTracking().FirstOrDefaultAsync(c => c.Id == userId);
            Assert.NotNull(cred);
            Assert.True(hasher.VerifyPassword("BrandNewP@ss123!", cred!.PasswordHash));

            var user = await db.Users.AsNoTracking().FirstAsync(u => u.Id == userId);
            Assert.Null(user.PasswordResetToken);
            Assert.Null(user.PasswordResetTokenExpiresAt);
            Assert.True(user.EmailVerified);
        }
    }

    [Fact]
    public async Task Reset_ExistingCredential_UpdatesHashAndClearsToken()
    {
        var userId = Guid.NewGuid();
        const string token = "existing-cred-token-1";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            db.Users.Add(new UserEntity
            {
                Id = userId,
                Email = "haspw@example.com",
                FirstName = "Has",
                LastName = "Pw",
                IsActive = true,
                EmailVerified = true,
                PasswordResetToken = token,
                PasswordResetTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            });
            db.UserCredentials.Add(new UserCredentialEntity
            {
                Id = userId,
                PasswordHash = hasher.HashPassword("OldP@ssword123!"),
                CreatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        using (var scope = _factory.Services.CreateScope())
        {
            var auth = scope.ServiceProvider.GetRequiredService<IAuthService>();
            Assert.True(await auth.ResetPasswordWithTokenAsync(token, "RotatedP@ss123!"));
        }

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            var cred = await db.UserCredentials.AsNoTracking().FirstAsync(c => c.Id == userId);
            Assert.True(hasher.VerifyPassword("RotatedP@ss123!", cred.PasswordHash));
            Assert.False(hasher.VerifyPassword("OldP@ssword123!", cred.PasswordHash));
            var user = await db.Users.AsNoTracking().FirstAsync(u => u.Id == userId);
            Assert.Null(user.PasswordResetToken);
        }
    }
}

public class PasswordResetMistakeTests : IClassFixture<PasswordResetRealValidatorFactory>
{
    private readonly PasswordResetRealValidatorFactory _factory;
    public PasswordResetMistakeTests(PasswordResetRealValidatorFactory factory) => _factory = factory;

    [Fact]
    public async Task Reset_InvalidPassword_ThrowsAndKeepsTokenUsable()
    {
        // A weak password must NOT consume the link — the user can retry.
        var userId = Guid.NewGuid();
        const string token = "retry-token-1";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            db.Users.Add(new UserEntity
            {
                Id = userId,
                Email = "retry@example.com",
                FirstName = "Re",
                LastName = "Try",
                IsActive = true,
                EmailVerified = false,
                PasswordResetToken = token,
                PasswordResetTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            });
            await db.SaveChangesAsync();
        }

        // Act — a too-short password fails real validation.
        using (var scope = _factory.Services.CreateScope())
        {
            var auth = scope.ServiceProvider.GetRequiredService<IAuthService>();
            await Assert.ThrowsAsync<ArgumentException>(() => auth.ResetPasswordWithTokenAsync(token, "short"));
        }

        // Assert — token still present (link not burned), no partial credential created.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var user = await db.Users.AsNoTracking().FirstAsync(u => u.Id == userId);
            Assert.Equal(token, user.PasswordResetToken);
            var cred = await db.UserCredentials.AsNoTracking().FirstOrDefaultAsync(c => c.Id == userId);
            Assert.Null(cred);
        }
    }
}

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;
using NetworcoId.Services;
using NetworcoId.Services.Messaging;
using NetworcoId.Services.System;
using NATS.Client.Core;
using Moq;
using Xunit;

namespace NetworcoId.Tests.Integration;

/// <summary>
/// Regression tests for account lockout accounting. The bug these pin down: an
/// attempt made while the account was already locked used to re-arm LockedUntil to
/// now + LockoutDurationMinutes — even when the password was correct — so a
/// 15-minute lock renewed itself indefinitely and a password reset never stuck.
/// </summary>
public sealed class LoginLockoutFactory : WebApplicationFactory<Program>
{
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

            services.AddDbContext<AuthDbContext>(options => options.UseInMemoryDatabase("LockoutTestDb"));

            var mockNats = new Mock<INatsConnection>();
            mockNats.Setup(n => n.Opts).Returns(new NatsOpts());
            services.AddSingleton<INatsConnection>(mockNats.Object);

            // No outbound email in tests (the lockout notice would otherwise be sent).
            services.AddSingleton<IEmailService>(new Mock<IEmailService>().Object);

            var bootstrap = services.SingleOrDefault(d => d.ServiceType == typeof(IBootstrapService));
            if (bootstrap != null) services.Remove(bootstrap);
            services.AddScoped<IBootstrapService, NoopBootstrap>();

            services.AddDataProtection();

            var mockValidator = new Mock<IPasswordValidator>();
            mockValidator.Setup(v => v.Validate(
                    It.IsAny<string>(), It.IsAny<int>(), It.IsAny<bool>(),
                    It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<bool>()))
                .Returns((true, null));
            services.AddSingleton<IPasswordValidator>(mockValidator.Object);
        });
    }

    private sealed class NoopBootstrap : IBootstrapService
    {
        public Task BootstrapAsync() => Task.CompletedTask;
    }
}

public class LoginLockoutTests : IClassFixture<LoginLockoutFactory>
{
    private const string GoodPassword = "CorrectHorse@1234";
    private const string BadPassword = "WrongHorse@1234";

    private readonly LoginLockoutFactory _factory;
    public LoginLockoutTests(LoginLockoutFactory factory) => _factory = factory;

    private NetworcoIdConfig Config => _factory.Services.GetRequiredService<NetworcoIdConfig>();

    /// <summary>Creates a verified, active account with a known password. Returns its id.</summary>
    private async Task<Guid> CreateUserAsync(string email, Action<UserCredentialEntity>? tweakCredential = null)
    {
        var userId = Guid.NewGuid();
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

        db.Users.Add(new UserEntity
        {
            Id = userId,
            Email = email,
            FirstName = "Lock",
            LastName = "Test",
            IsActive = true,
            EmailVerified = true,
        });

        var cred = new UserCredentialEntity
        {
            Id = userId,
            PasswordHash = hasher.HashPassword(GoodPassword),
            CreatedAt = DateTimeOffset.UtcNow,
        };
        tweakCredential?.Invoke(cred);
        db.UserCredentials.Add(cred);

        await db.SaveChangesAsync();
        return userId;
    }

    private async Task<AuthenticationResult> AuthenticateAsync(string email, string password)
    {
        using var scope = _factory.Services.CreateScope();
        var auth = scope.ServiceProvider.GetRequiredService<IAuthService>();
        return await auth.AuthenticateAsync(email, password);
    }

    private async Task<UserCredentialEntity> GetCredentialAsync(Guid userId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        return await db.UserCredentials.AsNoTracking().FirstAsync(c => c.Id == userId);
    }

    private async Task MutateCredentialAsync(Guid userId, Action<UserCredentialEntity> mutate)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var cred = await db.UserCredentials.FirstAsync(c => c.Id == userId);
        mutate(cred);
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Lock_TripsAtConfiguredThreshold_NotEarlier()
    {
        // The page used to increment the counter a second time on top of AuthService,
        // so the effective threshold was half the configured MaxFailedLoginAttempts.
        var max = Config.MaxFailedLoginAttempts;
        var userId = await CreateUserAsync("threshold@example.com");

        for (var attempt = 1; attempt < max; attempt++)
        {
            var interim = await AuthenticateAsync("threshold@example.com", BadPassword);
            Assert.Equal(AuthenticationOutcome.InvalidCredentials, interim.Outcome);

            var interimCred = await GetCredentialAsync(userId);
            Assert.Equal(attempt, interimCred.FailedLoginAttempts);
            Assert.Null(interimCred.LockedUntil);
        }

        var final = await AuthenticateAsync("threshold@example.com", BadPassword);
        Assert.Equal(AuthenticationOutcome.Locked, final.Outcome);
        Assert.True(final.PasswordWasChecked); // this attempt did check a password
        Assert.NotNull(final.LockedUntil);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(max, cred.FailedLoginAttempts);
        Assert.NotNull(cred.LockedUntil);
        Assert.True(cred.LockedUntil > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task ActiveLock_IsNotExtendedByFurtherAttempts()
    {
        var userId = await CreateUserAsync("norenew@example.com");
        var lockedUntil = DateTimeOffset.UtcNow.AddMinutes(5);
        await MutateCredentialAsync(userId, c =>
        {
            c.FailedLoginAttempts = Config.MaxFailedLoginAttempts;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow;
            c.LockedUntil = lockedUntil;
        });

        // Both a wrong password AND the correct one must bounce without touching state.
        foreach (var password in new[] { BadPassword, GoodPassword })
        {
            var result = await AuthenticateAsync("norenew@example.com", password);

            Assert.Equal(AuthenticationOutcome.Locked, result.Outcome);
            Assert.False(result.PasswordWasChecked); // refused before the password check
            Assert.Equal(lockedUntil, result.LockedUntil);

            var cred = await GetCredentialAsync(userId);
            Assert.Equal(lockedUntil, cred.LockedUntil);
            Assert.Equal(Config.MaxFailedLoginAttempts, cred.FailedLoginAttempts);
        }
    }

    [Fact]
    public async Task ExpiredLock_LetsCorrectPasswordThroughAndClearsState()
    {
        var userId = await CreateUserAsync("expired@example.com");
        await MutateCredentialAsync(userId, c =>
        {
            c.FailedLoginAttempts = Config.MaxFailedLoginAttempts;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow.AddMinutes(-30);
            c.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(-1);
        });

        var result = await AuthenticateAsync("expired@example.com", GoodPassword);

        Assert.Equal(AuthenticationOutcome.Success, result.Outcome);
        Assert.Equal(userId, result.User!.Id);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(0, cred.FailedLoginAttempts);
        Assert.Null(cred.LastFailedLoginAt);
        Assert.Null(cred.LockedUntil);
    }

    [Fact]
    public async Task ExpiredLock_DoesNotRelockOnTheNextSingleTypo()
    {
        // Without decay the account stays parked at the threshold, so one typo after
        // the lock expires re-locks it immediately.
        var userId = await CreateUserAsync("nopark@example.com");
        await MutateCredentialAsync(userId, c =>
        {
            c.FailedLoginAttempts = Config.MaxFailedLoginAttempts;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow.AddMinutes(-30);
            c.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(-1);
        });

        var result = await AuthenticateAsync("nopark@example.com", BadPassword);

        Assert.Equal(AuthenticationOutcome.InvalidCredentials, result.Outcome);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(1, cred.FailedLoginAttempts); // counter decayed, then counted this one
        Assert.Null(cred.LockedUntil);
    }

    [Fact]
    public async Task StaleFailures_DecayOutsideTheTrackingWindow()
    {
        var userId = await CreateUserAsync("decay@example.com");
        await MutateCredentialAsync(userId, c =>
        {
            c.FailedLoginAttempts = Config.MaxFailedLoginAttempts - 1;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow
                .AddMinutes(-(Config.FailedLoginAttemptWindowMinutes + 1));
        });

        var result = await AuthenticateAsync("decay@example.com", BadPassword);

        Assert.Equal(AuthenticationOutcome.InvalidCredentials, result.Outcome);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(1, cred.FailedLoginAttempts);
        Assert.Null(cred.LockedUntil);
    }

    [Fact]
    public async Task RecentFailures_StillCountInsideTheTrackingWindow()
    {
        // The decay must not hand out free attempts to an active guesser.
        var userId = await CreateUserAsync("nodecay@example.com");
        await MutateCredentialAsync(userId, c =>
        {
            c.FailedLoginAttempts = Config.MaxFailedLoginAttempts - 1;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        });

        var result = await AuthenticateAsync("nodecay@example.com", BadPassword);

        Assert.Equal(AuthenticationOutcome.Locked, result.Outcome);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(Config.MaxFailedLoginAttempts, cred.FailedLoginAttempts);
        Assert.NotNull(cred.LockedUntil);
    }

    [Fact]
    public async Task SuccessfulLogin_ClearsFailureState()
    {
        var userId = await CreateUserAsync("clears@example.com");
        await MutateCredentialAsync(userId, c =>
        {
            c.FailedLoginAttempts = 2;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        });

        var result = await AuthenticateAsync("clears@example.com", GoodPassword);
        Assert.Equal(AuthenticationOutcome.Success, result.Outcome);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(0, cred.FailedLoginAttempts);
        Assert.Null(cred.LastFailedLoginAt);
        Assert.Null(cred.LockedUntil);
    }

    [Fact]
    public async Task UnknownIdentifier_ReportsThatNoPasswordWasChecked()
    {
        // Login.cshtml.cs gates the IP throttle on outcome + this flag. Pin the flag so
        // a future "tidy-up" can't quietly stop charging IP failures for the paths that
        // should charge them (spraying, email enumeration) — or start charging for the
        // one that shouldn't (an attempt bounced by an already-active lock).
        var unknown = await AuthenticateAsync("nobody-here@example.com", BadPassword);
        Assert.Equal(AuthenticationOutcome.InvalidCredentials, unknown.Outcome);
        Assert.False(unknown.PasswordWasChecked);

        var userId = await CreateUserAsync("checked@example.com");
        var wrong = await AuthenticateAsync("checked@example.com", BadPassword);
        Assert.Equal(AuthenticationOutcome.InvalidCredentials, wrong.Outcome);
        Assert.True(wrong.PasswordWasChecked);

        await MutateCredentialAsync(userId, c => c.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(5));
        var locked = await AuthenticateAsync("checked@example.com", GoodPassword);
        Assert.Equal(AuthenticationOutcome.Locked, locked.Outcome);
        Assert.False(locked.PasswordWasChecked);
    }

    [Fact]
    public async Task PasswordReset_UnlocksTheAccountAndTheUnlockSticks()
    {
        const string newPassword = "FreshlyReset@9876";
        const string token = "lockout-reset-token-1";

        var userId = await CreateUserAsync("resetunlock@example.com", c =>
        {
            c.FailedLoginAttempts = 5;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow;
            c.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(15);
            c.LockoutStrikes = 3;
        });

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var user = await db.Users.FirstAsync(u => u.Id == userId);
            user.PasswordResetToken = token;
            user.PasswordResetTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1);
            await db.SaveChangesAsync();
        }

        using (var scope = _factory.Services.CreateScope())
        {
            var auth = scope.ServiceProvider.GetRequiredService<IAuthService>();
            Assert.True(await auth.ResetPasswordWithTokenAsync(token, newPassword));
        }

        var afterReset = await GetCredentialAsync(userId);
        Assert.Equal(0, afterReset.FailedLoginAttempts);
        Assert.Null(afterReset.LastFailedLoginAt);
        Assert.Null(afterReset.LockedUntil);
        Assert.Equal(0, afterReset.LockoutStrikes);

        // The unlock must survive contact with the login form: a wrong password
        // afterwards costs one attempt, and the new password still works.
        var typo = await AuthenticateAsync("resetunlock@example.com", BadPassword);
        Assert.Equal(AuthenticationOutcome.InvalidCredentials, typo.Outcome);

        var success = await AuthenticateAsync("resetunlock@example.com", newPassword);
        Assert.Equal(AuthenticationOutcome.Success, success.Outcome);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(0, cred.FailedLoginAttempts);
        Assert.Null(cred.LockedUntil);
    }

    [Fact]
    public async Task SecondLockout_LastsTwiceAsLong()
    {
        // Escalation: the first lock is the base duration; a second lockout without
        // an intervening successful login doubles it.
        var max = Config.MaxFailedLoginAttempts;
        var baseMinutes = Config.LockoutDurationMinutes;
        var userId = await CreateUserAsync("escalate@example.com");

        for (var i = 0; i < max; i++)
        {
            await AuthenticateAsync("escalate@example.com", BadPassword);
        }
        var afterFirst = await GetCredentialAsync(userId);
        Assert.Equal(1, afterFirst.LockoutStrikes);
        AssertLockDurationCloseTo(afterFirst.LockedUntil, baseMinutes);

        // Expire the lock, keeping the last failure recent so strikes survive.
        await MutateCredentialAsync(userId, c =>
        {
            c.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(-1);
            c.LastFailedLoginAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        });

        for (var i = 0; i < max; i++)
        {
            await AuthenticateAsync("escalate@example.com", BadPassword);
        }
        var afterSecond = await GetCredentialAsync(userId);
        Assert.Equal(2, afterSecond.LockoutStrikes);
        AssertLockDurationCloseTo(afterSecond.LockedUntil, baseMinutes * 2);
    }

    [Fact]
    public async Task Escalation_IsCappedAtSixteenTimesTheBaseDuration()
    {
        var max = Config.MaxFailedLoginAttempts;
        var baseMinutes = Config.LockoutDurationMinutes;
        var userId = await CreateUserAsync("capped@example.com", c =>
        {
            // Far beyond the cap exponent: the multiplier must clamp at 2^4 = 16.
            c.LockoutStrikes = 10;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow;
        });

        for (var i = 0; i < max; i++)
        {
            await AuthenticateAsync("capped@example.com", BadPassword);
        }

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(11, cred.LockoutStrikes);
        AssertLockDurationCloseTo(cred.LockedUntil, baseMinutes * 16);
    }

    [Fact]
    public async Task SuccessfulLogin_ResetsStrikes()
    {
        var userId = await CreateUserAsync("strikereset@example.com", c =>
        {
            c.LockoutStrikes = 3;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow;
        });

        var result = await AuthenticateAsync("strikereset@example.com", GoodPassword);
        Assert.Equal(AuthenticationOutcome.Success, result.Outcome);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(0, cred.LockoutStrikes);
    }

    [Fact]
    public async Task Strikes_AreForgottenAfterADayWithoutFailures()
    {
        // Escalation punishes bursts, not history: a typo a month after the last
        // lockout must lock (if it ever gets that far) at the base duration again.
        var userId = await CreateUserAsync("strikedecay@example.com", c =>
        {
            c.LockoutStrikes = 3;
            c.LastFailedLoginAt = DateTimeOffset.UtcNow.AddHours(-25);
        });

        var result = await AuthenticateAsync("strikedecay@example.com", BadPassword);
        Assert.Equal(AuthenticationOutcome.InvalidCredentials, result.Outcome);

        var cred = await GetCredentialAsync(userId);
        Assert.Equal(0, cred.LockoutStrikes); // decayed; a plain failure adds none
        Assert.Equal(1, cred.FailedLoginAttempts);
    }

    /// <summary>The lock deadline should sit at now + expectedMinutes, give or take
    /// test scheduling slack.</summary>
    private static void AssertLockDurationCloseTo(DateTimeOffset? lockedUntil, int expectedMinutes)
    {
        Assert.NotNull(lockedUntil);
        var remaining = lockedUntil!.Value - DateTimeOffset.UtcNow;
        Assert.InRange(remaining, TimeSpan.FromMinutes(expectedMinutes - 1), TimeSpan.FromMinutes(expectedMinutes + 1));
    }
}

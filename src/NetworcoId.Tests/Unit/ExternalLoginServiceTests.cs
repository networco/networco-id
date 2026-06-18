using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NATS.Client.Core;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;
using NetworcoId.Services;
using NetworcoId.Services.Audit;
using NetworcoId.Services.Messaging;
using Xunit;

namespace NetworcoId.Tests.Unit;

/// <summary>
/// Unit tests for the BankID/IDura find-or-create logic in <see cref="AuthService"/>.
/// Exercises the three account branches and link reuse against an InMemory DB.
/// </summary>
public class ExternalLoginServiceTests
{
    private const string Provider = "idura";

    private static AuthService BuildService(out AuthDbContext context)
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase("ExternalLoginTests_" + Guid.NewGuid())
            .ConfigureWarnings(w => w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        context = new AuthDbContext(options);

        var config = new NetworcoIdConfig { Issuer = "https://test", Audience = "networco-api" };
        var audit = new Mock<IAuditService>();
        audit.Setup(a => a.LogAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<string?>()))
             .Returns(Task.CompletedTask);

        return new AuthService(
            context,
            new Mock<IPasswordHasher>().Object,
            NullLogger<AuthService>.Instance,
            config,
            audit.Object,
            new Mock<IEmailService>().Object,
            new Mock<INatsConnection>().Object,
            new Mock<IPasswordValidator>().Object,
            new Mock<IAuthCodeStore>().Object);
    }

    [Fact]
    public async Task VerifiedEmail_LinksToExistingAccount()
    {
        var service = BuildService(out var context);
        var existing = new UserEntity
        {
            Id = Guid.NewGuid(),
            Email = "kari@example.com",
            FirstName = "Kari",
            LastName = "Nordmann",
            EmailVerified = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Users.Add(existing);
        await context.SaveChangesAsync();

        var info = new ExternalUserInfo
        {
            Subject = "idura-sub-1",
            Email = "kari@example.com",
            EmailVerified = true,
            FirstName = "Kari",
            LastName = "Nordmann",
            BirthDate = "1985-04-12"
        };

        var result = await service.FindOrCreateExternalUserAsync(Provider, info);

        Assert.Equal(existing.Id, result.Id); // linked, not a new account
        Assert.Equal(1, await context.Users.CountAsync());
        var link = await context.UserExternalLogins.SingleAsync();
        Assert.Equal(existing.Id, link.UserId);
        Assert.Equal("1985-04-12", (await context.Users.FindAsync(existing.Id))!.BirthDate);
    }

    [Fact]
    public async Task UnverifiedEmail_CreatesSeparateAccount_NotLinkedToExisting()
    {
        var service = BuildService(out var context);
        var existing = new UserEntity
        {
            Id = Guid.NewGuid(),
            Email = "ola@example.com",
            FirstName = "Ola",
            LastName = "Nordmann",
            EmailVerified = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Users.Add(existing);
        await context.SaveChangesAsync();

        // Same email, but the provider does NOT assert it verified → must not hijack.
        var info = new ExternalUserInfo
        {
            Subject = "idura-sub-2",
            Email = "ola@example.com",
            EmailVerified = false,
            FirstName = "Ola",
            LastName = "Nordmann"
        };

        var result = await service.FindOrCreateExternalUserAsync(Provider, info);

        Assert.NotEqual(existing.Id, result.Id);
        Assert.Equal(2, await context.Users.CountAsync());
        Assert.False(result.EmailVerified);
        Assert.EndsWith("@no-reply.networco.no", result.Email); // placeholder
    }

    [Fact]
    public async Task NoEmail_CreatesAccountWithUniquePlaceholder()
    {
        var service = BuildService(out var context);
        var info = new ExternalUserInfo
        {
            Subject = "idura-sub-3",
            FirstName = "Per",
            LastName = "Hansen",
            BirthDate = "1990-01-01"
        };

        var result = await service.FindOrCreateExternalUserAsync(Provider, info);

        Assert.Single(await context.Users.ToListAsync());
        Assert.False(result.EmailVerified);
        // Short, deterministic placeholder: bankid-<12 hex>@no-reply.networco.no
        Assert.Matches(@"^bankid-[0-9a-f]{12}@no-reply\.networco\.no$", result.Email);
        Assert.Equal("1990-01-01", result.BirthDate);
        Assert.Null(await context.UserCredentials.FirstOrDefaultAsync()); // password-less
    }

    [Fact]
    public async Task SecondLogin_ReusesExistingLink_NoDuplicateUser()
    {
        var service = BuildService(out var context);
        var info = new ExternalUserInfo
        {
            Subject = "idura-sub-4",
            FirstName = "Liv",
            LastName = "Berg"
        };

        var first = await service.FindOrCreateExternalUserAsync(Provider, info);
        var second = await service.FindOrCreateExternalUserAsync(Provider, info);

        Assert.Equal(first.Id, second.Id);
        Assert.Equal(1, await context.Users.CountAsync());
        Assert.Equal(1, await context.UserExternalLogins.CountAsync());
    }

    [Fact]
    public async Task UnverifiedEmail_NoCollision_StoredOnNewAccount()
    {
        var service = BuildService(out var context);
        var info = new ExternalUserInfo
        {
            Subject = "idura-sub-5",
            Email = "test@testesen.no",
            EmailVerified = false, // self-asserted on the BankID consent screen
            FirstName = "Test",
            LastName = "Testesen"
        };

        var result = await service.FindOrCreateExternalUserAsync(Provider, info);

        // The real (unverified) email is stored, not a placeholder.
        Assert.Equal("test@testesen.no", result.Email);
        Assert.False(result.EmailVerified);
    }

    [Fact]
    public async Task SecondLogin_BackfillsPlaceholderEmail()
    {
        var service = BuildService(out var context);

        // First login with no email → placeholder.
        var first = await service.FindOrCreateExternalUserAsync(Provider, new ExternalUserInfo
        {
            Subject = "idura-sub-6",
            FirstName = "Kari",
            LastName = "Nordmann"
        });
        Assert.EndsWith("@no-reply.networco.no", first.Email);

        // Same identity logs in again, now providing an email → backfilled onto the account.
        var second = await service.FindOrCreateExternalUserAsync(Provider, new ExternalUserInfo
        {
            Subject = "idura-sub-6",
            Email = "kari@example.com",
            EmailVerified = false,
            FirstName = "Kari",
            LastName = "Nordmann"
        });

        Assert.Equal(first.Id, second.Id);
        Assert.Equal("kari@example.com", second.Email);
        Assert.False(second.EmailVerified);
        Assert.Equal(1, await context.Users.CountAsync());
    }
}

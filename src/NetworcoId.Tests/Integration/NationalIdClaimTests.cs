using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NetworcoId.Infrastructure.Auth;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services;
using Xunit;

namespace NetworcoId.Tests.Integration;

/// <summary>
/// The <c>national_id</c> claim must only ever carry a real national id. Password login
/// used to fill it with the user's phone or email when they had none, so the claim was a
/// stand-in after login and missing after a refresh; networco-app hashed it as a
/// fødselsnummer, missed on every request and rewrote the user's profile each time.
/// </summary>
public class NationalIdClaimTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string? _originalDbUrl;

    private const string Password = "TestPassword123!";
    private const string EmailOnly = "no.nid@networco.dev";
    private const string WithNid = "has.nid@networco.dev";
    private const string RealNationalId = "12345678901";
    private static readonly string[] Scopes = ["openid", "profile", "email", "phone", "offline_access"];

    public NationalIdClaimTests(WebApplicationFactory<Program> factory)
    {
        _originalDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
        Environment.SetEnvironmentVariable("DATABASE_URL", "InMemory");

        var dbName = "NationalIdClaimTestDb_" + Guid.NewGuid();

        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:DefaultConnection", "InMemory");
            builder.UseSetting("Nats:ProvisionStreams", "false");

            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<AuthDbContext>>();
                services.RemoveAll<DbContextOptions>();
                services.RemoveAll<AuthDbContext>();
                services.RemoveAll<IDbContextFactory<AuthDbContext>>();

                Action<DbContextOptionsBuilder> configureOptions = options =>
                {
                    options.UseInMemoryDatabase(dbName);
                    options.ConfigureWarnings(x => x.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning));
                };

                services.AddDbContextFactory<AuthDbContext>(configureOptions, ServiceLifetime.Singleton);
                services.AddDbContext<AuthDbContext>(configureOptions, ServiceLifetime.Scoped, ServiceLifetime.Singleton);
            });
        });

        Seed();
    }

    public void Dispose() => Environment.SetEnvironmentVariable("DATABASE_URL", _originalDbUrl);

    private void Seed()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<NetworcoId.Core.Security.IPasswordHasher>();

        void Add(string email, string? nationalId)
        {
            var user = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = email,
                FirstName = "Claim",
                LastName = "Tester",
                NationalId = nationalId,
                // A phone number too: it was the first stand-in the old fallback picked.
                PhoneNumber = "+4799999999",
                IsActive = true,
                EmailVerified = true, // password login is blocked for unverified emails
                CreatedAt = DateTimeOffset.UtcNow
            };
            db.Users.Add(user);
            db.UserCredentials.Add(new UserCredentialEntity
            {
                Id = user.Id,
                PasswordHash = hasher.HashPassword(Password),
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        Add(EmailOnly, nationalId: null);
        Add(WithNid, RealNationalId);
        db.SaveChanges();
    }

    private async Task<JwtSecurityToken> PasswordLoginTokenAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var auth = scope.ServiceProvider.GetRequiredService<IAuthService>();
        var jwt = scope.ServiceProvider.GetRequiredService<IJwtService>();

        var result = await auth.AuthenticateAsync(email, Password);
        Assert.NotNull(result.User);

        var token = await jwt.GenerateAccessTokenAsync(result.User!, "networco-api", Scopes);
        return new JwtSecurityTokenHandler().ReadJwtToken(token);
    }

    [Fact]
    public async Task Password_login_without_a_national_id_issues_no_national_id_claim()
    {
        var token = await PasswordLoginTokenAsync(EmailOnly);

        Assert.DoesNotContain(token.Claims, c => c.Type == "national_id");
    }

    [Fact]
    public async Task Password_login_with_a_national_id_issues_it_as_the_claim()
    {
        var token = await PasswordLoginTokenAsync(WithNid);

        Assert.Equal(RealNationalId, Assert.Single(token.Claims, c => c.Type == "national_id").Value);
    }

    [Fact]
    public async Task Code_exchange_user_lookup_has_no_stand_in_national_id()
    {
        // The authorization-code exchange resolves the user through this lookup before
        // minting tokens, so it must not reintroduce the stand-in either.
        using var scope = _factory.Services.CreateScope();
        var auth = scope.ServiceProvider.GetRequiredService<IAuthService>();

        var user = await auth.GetUserByEmailOrNationalIdAsync(EmailOnly);

        Assert.NotNull(user);
        Assert.Equal("", user!.NationalId);
    }
}

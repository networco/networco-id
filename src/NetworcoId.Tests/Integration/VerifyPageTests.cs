using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using Xunit;

namespace NetworcoId.Tests.Integration;

/// <summary>
/// Covers the /verify page reached from the registration email — in particular
/// that opening the link a second time (double click, refresh) tells the user
/// they're already confirmed instead of showing a rejection-looking error.
/// </summary>
public class VerifyPageTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string? _originalDbUrl;
    private readonly HttpClient _client;

    private const string Token = "verify-page-test-token";

    public VerifyPageTests(WebApplicationFactory<Program> factory)
    {
        _originalDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
        Environment.SetEnvironmentVariable("DATABASE_URL", "InMemory");

        var dbName = "VerifyPageTestDb_" + Guid.NewGuid();

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

        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        db.Users.Add(new UserEntity
        {
            Id = Guid.NewGuid(),
            Email = "verify.page@networco.dev",
            FirstName = "Verify",
            LastName = "Page",
            IsActive = true,
            EmailVerified = false,
            EmailVerificationToken = Token,
            EmailVerificationTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30),
            EmailVerificationSessionId = "some-other-browser",
            CreatedAt = DateTimeOffset.UtcNow,
        });
        db.SaveChanges();
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("DATABASE_URL", _originalDbUrl);
    }

    [Fact]
    public async Task Verify_SecondClick_ShowsAlreadyConfirmed()
    {
        var first = await _client.GetAsync($"/verify?token={Token}");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var firstBody = await first.Content.ReadAsStringAsync();
        Assert.Contains("E-post bekreftet", firstBody);

        var second = await _client.GetAsync($"/verify?token={Token}");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var secondBody = await second.Content.ReadAsStringAsync();
        Assert.Contains("Du har allerede klikket på lenken og bekreftet.", secondBody);
        Assert.DoesNotContain("Bekreftelse mislyktes", secondBody);
    }

    [Fact]
    public async Task Verify_UnknownToken_StillShowsError()
    {
        var response = await _client.GetAsync("/verify?token=does-not-exist");
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Bekreftelse mislyktes", body);
    }
}

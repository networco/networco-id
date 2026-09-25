using System.Net;
using System.Text.RegularExpressions;
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
        Assert.Contains("E-posten din er bekreftet", secondBody);
        Assert.Contains("Gå til innlogging", secondBody);
        Assert.DoesNotContain("Bekreftelse mislyktes", secondBody);
    }

    [Fact]
    public async Task Verify_SecondClick_WithAppLoginFlow_ResumesIt()
    {
        // Registration started from the app carries its /Login?client_id=… request
        // through the email link; the "already confirmed" button must resume it so
        // the user ends up back in the app rather than on the home page.
        var returnUrl = "/Login?client_id=networco-app&redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback&state=abc";
        var link = $"/verify?token={Token}&return_url={Uri.EscapeDataString(returnUrl)}";

        await _client.GetAsync(link);
        var body = await (await _client.GetAsync(link)).Content.ReadAsStringAsync();

        Assert.Contains("E-posten din er bekreftet", body);
        Assert.Contains("href=\"/Login?client_id=networco-app&amp;redirect_uri=", body);
    }

    [Fact]
    public async Task Verify_UnknownToken_StillShowsError()
    {
        var response = await _client.GetAsync("/verify?token=does-not-exist");
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Bekreftelse mislyktes", body);
    }

    [Fact]
    public async Task Resend_AlreadyVerified_TellsUserToLogIn()
    {
        await _client.GetAsync($"/verify?token={Token}");

        // Load the form like a browser would (the tokenless error page renders it)
        // to get the antiforgery cookie + field for the POST.
        var formPage = await (await _client.GetAsync("/verify")).Content.ReadAsStringAsync();
        var antiforgery = Regex.Match(formPage, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;

        var response = await _client.PostAsync("/verify?handler=Resend", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiforgery,
            ["resendEmail"] = "verify.page@networco.dev",
        }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Har du allerede bekreftet e-posten din, trenger du ingen ny lenke.", body);
    }
}

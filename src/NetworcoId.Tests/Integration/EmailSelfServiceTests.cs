using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using Xunit;

namespace NetworcoId.Tests.Integration;

/// <summary>
/// Covers the self-service email endpoints used by relying-party apps (e.g. the
/// NETWORCO app) to (re)send verification, change the address, and read the
/// server-side BankID/IDura login reference for the authenticated user.
/// </summary>
public class EmailSelfServiceTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string? _originalDbUrl;
    private readonly HttpClient _client;

    private const string TestEmail = "selfservice.test@networco.dev";
    private const string OtherEmail = "other.user@networco.dev";
    private const string TestPassword = "TestPassword123!";
    private const string ClientId = "selfservice-test-client";
    private const string ClientSecret = "test-secret";
    private const string RedirectUri = "http://localhost:3000/callback";

    private Guid _userId;

    public EmailSelfServiceTests(WebApplicationFactory<Program> factory)
    {
        _originalDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
        Environment.SetEnvironmentVariable("DATABASE_URL", "InMemory");

        var dbName = "EmailSelfServiceTestDb_" + Guid.NewGuid();

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

        SeedDatabase();
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("DATABASE_URL", _originalDbUrl);
    }

    private void SeedDatabase()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<NetworcoId.Core.Security.IPasswordHasher>();

        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            Email = TestEmail,
            FirstName = "Self",
            LastName = "Service",
            NationalId = "12345678901",
            IsActive = true,
            // Verified so the password login flow issues a token; individual tests
            // flip this to false in-DB when they need the unverified path.
            EmailVerified = true,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        _userId = user.Id;
        db.Users.Add(user);
        db.UserCredentials.Add(new UserCredentialEntity
        {
            Id = user.Id,
            PasswordHash = hasher.HashPassword(TestPassword),
            CreatedAt = DateTimeOffset.UtcNow
        });

        // A second user that already owns OtherEmail — used for the conflict test.
        var other = new UserEntity
        {
            Id = Guid.NewGuid(),
            Email = OtherEmail,
            FirstName = "Other",
            LastName = "User",
            NationalId = "10987654321",
            IsActive = true,
            EmailVerified = true,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        db.Users.Add(other);

        // A federated login reference for the primary user.
        db.UserExternalLogins.Add(new UserExternalLoginEntity
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Provider = "idura",
            Subject = "idura-subject-12345",
            CreatedAt = DateTimeOffset.UtcNow,
            LastLoginAt = DateTimeOffset.UtcNow,
        });

        db.OAuthClients.Add(new OAuthClientEntity
        {
            ClientId = ClientId,
            Audience = "networco-api",
            DisplayName = "Self-Service Test Client",
            PrimaryClientSecretHash = hasher.HashPassword(ClientSecret),
            RedirectUris = new List<string> { RedirectUri },
            AllowedScopes = new List<string> { "openid", "profile", "email", "phone" },
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });

        db.SaveChanges();
    }

    private async Task<string> GetAccessTokenAsync(string scopes = "openid profile email")
        => (await GetTokensAsync(scopes)).AccessToken;

    private async Task<(string AccessToken, string RefreshToken)> GetTokensAsync(string scopes = "openid profile email")
    {
        var state = "test-state";
        var authUrl = $"/oauth/authorize?response_type=code&client_id={ClientId}&redirect_uri={RedirectUri}&state={state}&scope={scopes}&code_challenge=challenge&code_challenge_method=plain";
        await _client.GetAsync(authUrl);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "Email", TestEmail },
            { "Password", TestPassword },
            { "client_id", ClientId },
            { "redirect_uri", RedirectUri },
            { "state", state },
            { "scope", scopes },
            { "code_challenge", "challenge" },
            { "code_challenge_method", "plain" }
        });

        var loginResponse = await _client.PostAsync("/Login", content);
        var callbackUrl = loginResponse.Headers.Location?.ToString()
            ?? throw new Exception($"Login failed: {await loginResponse.Content.ReadAsStringAsync()}");
        var code = System.Web.HttpUtility.ParseQueryString(new Uri(callbackUrl).Query)["code"];

        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code! },
            { "redirect_uri", RedirectUri },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "code_verifier", "challenge" }
        });

        var tokenResponse = await _client.PostAsync("/oauth/token", tokenRequest);
        var json = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        return (json.GetProperty("access_token").GetString()!, json.GetProperty("refresh_token").GetString()!);
    }

    private void Authorize(string token) =>
        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

    private UserEntity GetUser(Guid id)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        return db.Users.AsNoTracking().First(u => u.Id == id);
    }

    private void SetEmailVerified(bool verified)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var u = db.Users.First(u => u.Id == _userId);
        u.EmailVerified = verified;
        db.SaveChanges();
    }

    [Fact]
    public async Task SendVerification_Unverified_SetsTokenAndReturnsSent()
    {
        Authorize(await GetAccessTokenAsync());
        SetEmailVerified(false); // token already minted; endpoint reads state fresh from DB

        var response = await _client.PostAsJsonAsync("/auth/email/send-verification", new { returnUrl = "http://localhost:3000/" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("sent", body.GetProperty("status").GetString());

        var user = GetUser(_userId);
        Assert.False(string.IsNullOrEmpty(user.EmailVerificationToken));
        Assert.False(user.EmailVerified);
    }

    [Fact]
    public async Task SendVerification_AlreadyVerified_ReturnsAlreadyVerified()
    {
        // User is seeded already-verified.
        Authorize(await GetAccessTokenAsync());
        var response = await _client.PostAsJsonAsync("/auth/email/send-verification", new { });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("already_verified", body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task ChangeEmail_Valid_UpdatesEmailAndUnverifies()
    {
        Authorize(await GetAccessTokenAsync());

        const string newEmail = "brand.new@networco.dev";
        var response = await _client.PutAsJsonAsync("/auth/email", new { email = newEmail, returnUrl = "http://localhost:3000/" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var user = GetUser(_userId);
        Assert.Equal(newEmail, user.Email);
        Assert.False(user.EmailVerified);
        Assert.False(string.IsNullOrEmpty(user.EmailVerificationToken));
    }

    [Fact]
    public async Task ChangeEmail_InvalidatesActiveSessions()
    {
        // The OAuth flow in GetAccessTokenAsync persists a refresh token for the user.
        Authorize(await GetAccessTokenAsync());

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            Assert.True(db.RefreshTokens.Any(t => t.UserId == _userId && t.RevokedAt == null),
                "precondition: an active refresh token should exist after login");
        }

        var response = await _client.PutAsJsonAsync("/auth/email", new { email = "fresh.addr@networco.dev" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            // No active refresh tokens remain — stale identity can't be renewed.
            Assert.False(db.RefreshTokens.Any(t => t.UserId == _userId && t.RevokedAt == null));
            // Credential timestamp bumped so outstanding access tokens are rejected by the hook.
            var cred = db.UserCredentials.AsNoTracking().First(c => c.Id == _userId);
            Assert.NotNull(cred.UpdatedAt);
        }
    }

    [Fact]
    public async Task ChangeEmail_RevokedRefreshToken_CannotBeRenewedViaAuthRefresh()
    {
        // Regression: a token revoked by session invalidation (no successor) must be
        // rejected by /auth/refresh immediately — the rotation grace window must not
        // let it be rotated back into a fresh, active token.
        var (access, refresh) = await GetTokensAsync();
        Authorize(access);

        var change = await _client.PutAsJsonAsync("/auth/email", new { email = "after.change@networco.dev" });
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        _client.DefaultRequestHeaders.Authorization = null;
        var refreshResp = await _client.PostAsJsonAsync("/auth/refresh", new { refreshToken = refresh });

        Assert.NotEqual(HttpStatusCode.OK, refreshResp.StatusCode);
        // And it didn't get rotated into a new active token.
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.False(db.RefreshTokens.Any(t => t.UserId == _userId && t.RevokedAt == null));
    }

    [Fact]
    public async Task ChangeEmail_InvalidFormat_ReturnsBadRequest()
    {
        Authorize(await GetAccessTokenAsync());
        var response = await _client.PutAsJsonAsync("/auth/email", new { email = "not-an-email" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ChangeEmail_TakenByAnotherUser_ReturnsConflict()
    {
        Authorize(await GetAccessTokenAsync());
        var response = await _client.PutAsJsonAsync("/auth/email", new { email = OtherEmail });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);

        // Primary user keeps its original address.
        Assert.Equal(TestEmail, GetUser(_userId).Email);
    }

    [Fact]
    public async Task ExternalLogins_ReturnsSeededReference()
    {
        Authorize(await GetAccessTokenAsync());
        var response = await _client.GetAsync("/auth/external-logins");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var logins = body.GetProperty("externalLogins");
        Assert.Equal(1, logins.GetArrayLength());
        Assert.Equal("idura", logins[0].GetProperty("provider").GetString());
        Assert.Equal("idura-subject-12345", logins[0].GetProperty("subject").GetString());
    }

    [Fact]
    public async Task EmailEndpoints_WithoutToken_ReturnUnauthorized()
    {
        _client.DefaultRequestHeaders.Authorization = null;
        var send = await _client.PostAsJsonAsync("/auth/email/send-verification", new { });
        Assert.Equal(HttpStatusCode.Unauthorized, send.StatusCode);
    }
}

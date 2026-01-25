using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using Xunit;

namespace NetworcoId.Tests.Integration;

public class SecondarySecretTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string? _originalDbUrl;
    private readonly HttpClient _client;
    
    private const string TestEmail = "secondary.secret@networco.dev";
    private const string TestPassword = "TestPassword123!";
    private const string ClientId = "secondary-secret-client";
    private const string PrimarySecret = "primary-secret";
    private const string SecondarySecret = "secondary-secret";
    private const string RedirectUri = "http://localhost:3000/callback";

    public SecondarySecretTests(WebApplicationFactory<Program> factory)
    {
        _originalDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
        Environment.SetEnvironmentVariable("DATABASE_URL", "InMemory");

        var dbName = "SecondarySecretTestDb_" + Guid.NewGuid();

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
            FirstName = "Secondary",
            LastName = "Tester",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var hash = hasher.HashPassword(TestPassword);
        var cred = new UserCredentialEntity
        {
            Id = user.Id,
            PasswordHash = hash,
            CreatedAt = DateTimeOffset.UtcNow
        };

        db.Users.Add(user);
        db.UserCredentials.Add(cred);
        
        db.OAuthClients.Add(new OAuthClientEntity
        {
            ClientId = ClientId,
            Audience = "networco-api",
            DisplayName = "Secondary Secret Test Client",
            PrimaryClientSecretHash = hasher.HashPassword(PrimarySecret),
            SecondaryClientSecretHash = hasher.HashPassword(SecondarySecret),
            RedirectUris = new List<string> { RedirectUri },
            AllowedScopes = new List<string> { "openid", "profile", "email" },
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        
        db.SaveChanges();
    }

    [Fact]
    public async Task TokenExchange_WithSecondarySecret_Success()
    {
        // 1. Get an auth code first
        var state = "test-state";
        var (challenge, verifier) = GeneratePkce();
        
        // Login to get code
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "Email", TestEmail },
            { "Password", TestPassword },
            { "client_id", ClientId },
            { "redirect_uri", RedirectUri },
            { "state", state },
            { "code_challenge", challenge },
            { "code_challenge_method", "S256" }
        });

        var loginResponse = await _client.PostAsync("/Login", content);
        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        
        var callbackUrl = loginResponse.Headers.Location?.ToString();
        var query = new Uri(callbackUrl!).Query;
        var queryParams = System.Web.HttpUtility.ParseQueryString(query);
        var code = queryParams["code"];

        // 2. Exchange Code for Token using SECONDARY secret
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code! },
            { "redirect_uri", RedirectUri },
            { "client_id", ClientId },
            { "client_secret", SecondarySecret },
            { "code_verifier", verifier }
        });

        var tokenResponse = await _client.PostAsync("/oauth/token", tokenRequest);
        
        // Assert
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        var body = await tokenResponse.Content.ReadAsStringAsync();
        var tokenData = JsonDocument.Parse(body);
        Assert.True(tokenData.RootElement.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task TokenExchange_WithPrimarySecret_Success()
    {
        // 1. Get an auth code
        var state = "test-state";
        var (challenge, verifier) = GeneratePkce();
        
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "Email", TestEmail },
            { "Password", TestPassword },
            { "client_id", ClientId },
            { "redirect_uri", RedirectUri },
            { "state", state },
            { "code_challenge", challenge },
            { "code_challenge_method", "S256" }
        });

        var loginResponse = await _client.PostAsync("/Login", content);
        var callbackUrl = loginResponse.Headers.Location?.ToString();
        var query = new Uri(callbackUrl!).Query;
        var queryParams = System.Web.HttpUtility.ParseQueryString(query);
        var code = queryParams["code"];

        // 2. Exchange Code for Token using PRIMARY secret
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code! },
            { "redirect_uri", RedirectUri },
            { "client_id", ClientId },
            { "client_secret", PrimarySecret },
            { "code_verifier", verifier }
        });

        var tokenResponse = await _client.PostAsync("/oauth/token", tokenRequest);
        
        // Assert
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
    }

    [Fact]
    public async Task TokenExchange_WithInvalidSecret_Fails()
    {
        // 1. Get an auth code
        var state = "test-state";
        var (challenge, verifier) = GeneratePkce();
        
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "Email", TestEmail },
            { "Password", TestPassword },
            { "client_id", ClientId },
            { "redirect_uri", RedirectUri },
            { "state", state },
            { "code_challenge", challenge },
            { "code_challenge_method", "S256" }
        });

        var loginResponse = await _client.PostAsync("/Login", content);
        var callbackUrl = loginResponse.Headers.Location?.ToString();
        var query = new Uri(callbackUrl!).Query;
        var queryParams = System.Web.HttpUtility.ParseQueryString(query);
        var code = queryParams["code"];

        // 2. Exchange Code for Token using INVALID secret
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code! },
            { "redirect_uri", RedirectUri },
            { "client_id", ClientId },
            { "client_secret", "wrong-secret" },
            { "code_verifier", verifier }
        });

        var tokenResponse = await _client.PostAsync("/oauth/token", tokenRequest);
        
        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        var body = await tokenResponse.Content.ReadAsStringAsync();
        Assert.Contains("invalid_client", body);
    }

    private static (string challenge, string verifier) GeneratePkce()
    {
        var verifierBytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Convert.ToBase64String(verifierBytes)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(challengeBytes)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        return (challenge, verifier);
    }
}
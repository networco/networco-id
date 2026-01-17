using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using Xunit;

namespace NetworcoId.Tests.Integration;

public class PkceFlowTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;
    
    // Test user credentials
    private const string TestEmail = "pkce.test@networco.dev";
    private const string TestPassword = "TestPassword123!";
    private const string ClientId = "test-client";
    private const string ClientSecret = "test-secret";
    private const string RedirectUri = "http://localhost:3000/callback";

    public PkceFlowTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Aggressively remove existing database services to avoid "Multiple providers" error
                var dbContextOptions = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>));
                if (dbContextOptions != null) services.Remove(dbContextOptions);

                var dbContextOptionsGeneric = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions));
                if (dbContextOptionsGeneric != null) services.Remove(dbContextOptionsGeneric);

                var dbContext = services.SingleOrDefault(d => d.ServiceType == typeof(AuthDbContext));
                if (dbContext != null) services.Remove(dbContext);

                // Ensure no background workers or services are using the DB before we can replace it?
                // Actually, KeyManagementService might be registered with the old context type if it was added before removal?
                // No, it's scoped, so it resolves at request time.
                
                // Add InMemory DbContext
                services.AddDbContext<AuthDbContext>(options =>
                {
                    options.UseInMemoryDatabase("PkceTestDb");
                    options.ConfigureWarnings(x => x.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning));
                });
            });
            
            // Try to signal to DatabaseConfiguration to skip Npgsql registration
            builder.UseSetting("ConnectionStrings:DefaultConnection", "InMemory");
            
            // Disable NATS stream provisioning
            builder.UseSetting("Nats:ProvisionStreams", "false");
        });

        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false // We want to inspect 302 redirects
        });
        
        // Seed database
        SeedDatabase();
    }

    private void SeedDatabase()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        
        if (!db.Users.Any(u => u.Email == TestEmail))
        {
            var user = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = TestEmail,
                FirstName = "PKCE",
                LastName = "Tester",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
            
            // Password hash for "TestPassword123!" using default PBKDF2
            // Note: In a real test we might inject a hash, but since we use the real service 
            // we rely on the PasswordHasher. But for InMemory seeding we need a valid hash.
            // Let's create user via registration service instead? 
            // Actually simpler: just inject a known hash or use the service to create user in a test helper
            // For now, let's just assume we can register or manually insert.
            // We'll insert a dummy hash and bypass login if possible, OR use the IPasswordHasher to generate it.
            
            var hasher = scope.ServiceProvider.GetRequiredService<NetworcoId.Core.Security.IPasswordHasher>();
            var hash = hasher.HashPassword(TestPassword);

            var cred = new UserCredentialEntity
            {
                Id = user.Id,
                PasswordHash = hash,
                CreatedAt = DateTimeOffset.UtcNow
            };

            db.Users.Add(user);
            db.UserCredentials.Add(cred);
            
            // Add Client
            if (!db.OAuthClients.Any(c => c.ClientId == ClientId))
            {
                db.OAuthClients.Add(new OAuthClientEntity
                {
                    ClientId = ClientId,
                    DisplayName = "Test Client",
                    PrimaryClientSecretHash = hasher.HashPassword(ClientSecret),
                    RedirectUris = new List<string> { RedirectUri },
                    AllowedScopes = new List<string> { "openid", "profile", "email" },
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow
                });
            }
            
            db.SaveChanges();
        }
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

    [Fact]
    public async Task CompletePkceFlow_Success()
    {
        // 1. Generate PKCE params
        var (challenge, verifier) = GeneratePkce();
        var state = "test-state";

        // 2. Initiate Authorize Request
        var authUrl = $"/oauth/authorize?response_type=code&client_id={ClientId}&redirect_uri={RedirectUri}&state={state}&code_challenge={challenge}&code_challenge_method=S256";
        var authResponse = await _client.GetAsync(authUrl);
        
        // Should redirect to login page
        Assert.Equal(HttpStatusCode.Redirect, authResponse.StatusCode);
        var loginUrl = authResponse.Headers.Location?.ToString();
        Assert.Contains("/Login", loginUrl);
        Assert.Contains($"code_challenge={challenge}", loginUrl); // Verify params preserved
        
        // 3. Perform Login (POST to Login page)
        // Extract return URL or just post to /Login with query params
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
        
        // Should redirect back to client with code
        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        var callbackUrl = loginResponse.Headers.Location?.ToString();
        Assert.StartsWith(RedirectUri, callbackUrl);
        
        // Extract authorization code
        var query = new Uri(callbackUrl!).Query;
        var queryParams = System.Web.HttpUtility.ParseQueryString(query);
        var code = queryParams["code"];
        Assert.NotNull(code);

        // 4. Exchange Code for Token (with Verifier)
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code! },
            { "redirect_uri", RedirectUri },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "code_verifier", verifier } // Correct verifier
        });

        var tokenResponse = await _client.PostAsync("/oauth/token", tokenRequest);
        
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        var json = await tokenResponse.Content.ReadAsStringAsync();
        Assert.Contains("access_token", json);
    }

    [Fact]
    public async Task TokenExchange_WithWrongVerifier_Fails()
    {
        // 1. Generate PKCE params
        var (challenge, _) = GeneratePkce();
        var (_, wrongVerifier) = GeneratePkce();
        var state = "test-state-fail";

        // 2. Login flow to get code
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
        var code = System.Web.HttpUtility.ParseQueryString(query)["code"];

        // 3. Exchange Code for Token (with WRONG Verifier)
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code! },
            { "redirect_uri", RedirectUri },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "code_verifier", wrongVerifier } 
        });

        var tokenResponse = await _client.PostAsync("/oauth/token", tokenRequest);
        
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
    }

    [Fact]
    public async Task TokenExchange_MissingVerifier_WhenChallengeUsed_Fails()
    {
        // 1. Generate PKCE params
        var (challenge, _) = GeneratePkce();
        var state = "test-state-missing";

        // 2. Login flow to get code
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
        var code = System.Web.HttpUtility.ParseQueryString(query)["code"];

        // 3. Exchange Code for Token (without Verifier)
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code! },
            { "redirect_uri", RedirectUri },
            { "client_id", ClientId },
            { "client_secret", ClientSecret }
            // Missing code_verifier
        });

        var tokenResponse = await _client.PostAsync("/oauth/token", tokenRequest);
        
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
    }

    [Fact]
    public async Task Authorize_WithoutCodeChallenge_Fails()
    {
        // Act
        var authUrl = $"/oauth/authorize?response_type=code&client_id={ClientId}&redirect_uri={RedirectUri}&state=no-pkce";
        var authResponse = await _client.GetAsync(authUrl);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, authResponse.StatusCode);
        var json = await authResponse.Content.ReadAsStringAsync();
        Assert.Contains("code_challenge is required", json);
    }

    [Fact]
    public async Task Authorize_WithPlainMethod_Fails()
    {
        // Act
        var authUrl = $"/oauth/authorize?response_type=code&client_id={ClientId}&redirect_uri={RedirectUri}&state=plain-pkce&code_challenge=foo&code_challenge_method=plain";
        var authResponse = await _client.GetAsync(authUrl);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, authResponse.StatusCode);
        var json = await authResponse.Content.ReadAsStringAsync();
        Assert.Contains("code_challenge_method must be 'S256'", json);
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Models.Auth;
using Xunit;

namespace NetworcoId.Tests.Integration;

public class UserinfoScopeTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string? _originalDbUrl;
    private readonly HttpClient _client;
    
    private const string TestEmail = "scope.test@networco.dev";
    private const string TestPassword = "TestPassword123!";
    private const string ClientId = "scope-test-client";
    private const string ClientSecret = "test-secret";
    private const string RedirectUri = "http://localhost:3000/callback";

    public UserinfoScopeTests(WebApplicationFactory<Program> factory)
    {
        _originalDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
        Environment.SetEnvironmentVariable("DATABASE_URL", "InMemory");

        var dbName = "UserinfoScopeTestDb_" + Guid.NewGuid();

        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:DefaultConnection", "InMemory");
            builder.UseSetting("Nats:ProvisionStreams", "false");

            builder.ConfigureServices(services =>
            {
                // Cleanly remove existing database services
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

        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        
        SeedDatabase();
    }

    public void Dispose()
    {
        if (_originalDbUrl != null)
        {
            Environment.SetEnvironmentVariable("DATABASE_URL", _originalDbUrl);
        }
        else
        {
            Environment.SetEnvironmentVariable("DATABASE_URL", null);
        }
    }

    private void SeedDatabase()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<NetworcoId.Core.Security.IPasswordHasher>();
        
        if (!db.Users.Any(u => u.Email == TestEmail))
        {
            var user = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = TestEmail,
                FirstName = "Scope",
                LastName = "Tester",
                NationalId = "12345678901",
                PhoneNumber = "+4799999999",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
            
            var passwordHash = hasher.HashPassword(TestPassword);
            var cred = new UserCredentialEntity
            {
                Id = user.Id,
                PasswordHash = passwordHash,
                CreatedAt = DateTimeOffset.UtcNow
            };

            // Verify hash immediately to ensure test integrity
            if (!hasher.VerifyPassword(TestPassword, passwordHash))
            {
                throw new Exception($"Sanity check failed: Password hasher could not verify the password it just hashed. Hash: {passwordHash}");
            }

            db.Users.Add(user);
            db.UserCredentials.Add(cred);
            
            if (!db.OAuthClients.Any(c => c.ClientId == ClientId))
            {
                db.OAuthClients.Add(new OAuthClientEntity
                {
                    ClientId = ClientId,
                    Audience = "networco-api",
                    DisplayName = "Scope Test Client",
                    PrimaryClientSecretHash = hasher.HashPassword(ClientSecret),
                    RedirectUris = new List<string> { RedirectUri },
                    AllowedScopes = new List<string> { "openid", "profile", "email", "phone" },
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow
                });
            }
            
            db.SaveChanges();
        }
    }

    private async Task<string> GetAccessTokenAsync(string scopes)
    {
        // 1. Initiate Authorize Request
        var state = "test-state";
        var authUrl = $"/oauth/authorize?response_type=code&client_id={ClientId}&redirect_uri={RedirectUri}&state={state}&scope={scopes}&code_challenge=challenge&code_challenge_method=plain"; 
        var authResponse = await _client.GetAsync(authUrl);
        
        // 2. Login
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
        if (loginResponse.Headers.Location == null)
        {
            var error = await loginResponse.Content.ReadAsStringAsync();
            throw new Exception($"Login failed. Status: {loginResponse.StatusCode}, Content: {error}");
        }
        var callbackUrl = loginResponse.Headers.Location?.ToString();
        var query = new Uri(callbackUrl!).Query;
        var code = System.Web.HttpUtility.ParseQueryString(query)["code"];

        // 3. Exchange Code
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
        return json.GetProperty("access_token").GetString()!;
    }

    [Fact]
    public async Task Userinfo_WithProfileScope_ReturnsProfileClaims()
    {
        var token = await GetAccessTokenAsync("openid profile");
        
        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var response = await _client.GetAsync("/auth/me");
        var responseContent = await response.Content.ReadAsStringAsync();
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new Exception($"Userinfo failed with status {response.StatusCode}. Content: {responseContent}");
        }
        var claims = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        
        Assert.True(claims!.ContainsKey("given_name"), $"Expected given_name to be present. Claims: {string.Join(", ", claims.Keys)}");
        Assert.True(claims.ContainsKey("family_name"), "Expected family_name to be present");
        Assert.False(claims.ContainsKey("email"), "Expected email NOT to be present"); 
        Assert.False(claims.ContainsKey("phone_number"), "Expected phone_number NOT to be present"); 
    }

    [Fact]
    public async Task Userinfo_WithEmailScope_ReturnsEmailClaims()
    {
        var token = await GetAccessTokenAsync("openid email");
        
        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var response = await _client.GetAsync("/auth/me");
        var responseContent = await response.Content.ReadAsStringAsync();
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new Exception($"Userinfo failed with status {response.StatusCode}. Content: {responseContent}");
        }
        var claims = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        
        Assert.True(claims!.ContainsKey("email"), $"Expected email to be present. Claims: {string.Join(", ", claims.Keys)}");
        Assert.True(claims.ContainsKey("email_verified"), "Expected email_verified to be present");
        Assert.False(claims.ContainsKey("given_name"), "Expected given_name NOT to be present"); 
        Assert.False(claims.ContainsKey("family_name"), "Expected family_name NOT to be present");
    }

    [Fact]
    public async Task Userinfo_WithAllScopes_ReturnsAllClaims()
    {
        var token = await GetAccessTokenAsync("openid profile email phone");
        
        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var response = await _client.GetAsync("/auth/me");
        var responseContent = await response.Content.ReadAsStringAsync();
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new Exception($"Userinfo failed with status {response.StatusCode}. Content: {responseContent}");
        }
        var claims = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        
        Assert.True(claims!.ContainsKey("sub"), "Expected sub to be present");
        Assert.True(claims.ContainsKey("email"), "Expected email to be present");
        Assert.True(claims.ContainsKey("given_name"), "Expected given_name to be present");
        Assert.True(claims.ContainsKey("family_name"), "Expected family_name to be present");
        Assert.True(claims.ContainsKey("phone_number"), $"Expected phone_number to be present. Claims: {string.Join(", ", claims.Keys)}");
    }

    [Fact]
    public async Task Userinfo_WithOnlyOpenId_ReturnsMinimalClaims()
    {
        var token = await GetAccessTokenAsync("openid");
        
        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var response = await _client.GetAsync("/auth/me");
        var responseContent = await response.Content.ReadAsStringAsync();
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new Exception($"Userinfo failed with status {response.StatusCode}. Content: {responseContent}");
        }
        var claims = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        
        Assert.True(claims!.ContainsKey("sub"));
        Assert.False(claims.ContainsKey("email"));
        Assert.False(claims.ContainsKey("given_name"));
        Assert.False(claims.ContainsKey("family_name"));
        Assert.False(claims.ContainsKey("phone_number"));
    }
}

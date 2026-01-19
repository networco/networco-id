using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using Xunit;

namespace NetworcoId.Tests.Integration;

public class RefreshTokenTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string? _originalDbUrl;

    public RefreshTokenTests(WebApplicationFactory<Program> factory)
    {
        _originalDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
        Environment.SetEnvironmentVariable("DATABASE_URL", "InMemory");

        var dbName = "RefreshTokenTestDb_" + Guid.NewGuid();

        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:DefaultConnection", "InMemory");
            builder.UseSetting("NetworcoId:Nats:ProvisionStreams", "false");

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

    [Fact]
    public async Task RefreshToken_Flow_ShouldWork()
    {
        // Arrange
        var client = _factory.CreateClient();
        
        // Basic check that endpoint is reachable
        var tokenResponse = await client.PostAsync("/oauth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = "invalid_code",
            ["redirect_uri"] = "http://localhost/callback",
            ["client_id"] = "test_client", 
            ["client_secret"] = "test_secret"
        }));

        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
    }
}

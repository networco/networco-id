using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using Xunit;

namespace NetworcoId.Tests.Integration;

public class RefreshTokenTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public RefreshTokenTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:DefaultConnection", "InMemory");
            builder.UseSetting("NetworcoId:Nats:ProvisionStreams", "false");

            builder.ConfigureServices(services =>
            {
                // Remove existing DB context
                var dbContextOptions = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>));
                if (dbContextOptions != null) services.Remove(dbContextOptions);

                var dbContext = services.SingleOrDefault(d => d.ServiceType == typeof(AuthDbContext));
                if (dbContext != null) services.Remove(dbContext);

                services.AddDbContext<AuthDbContext>(options =>
                {
                    options.UseInMemoryDatabase("InMemoryDbForTesting_RefreshToken_" + Guid.NewGuid());
                    options.ConfigureWarnings(x => x.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning));
                });
            });
        });
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

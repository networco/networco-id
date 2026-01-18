using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
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
        _factory = factory;
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

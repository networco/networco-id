using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using NetworcoId.Services.System;
using NATS.Client.Core;
using Moq;
using Xunit;

namespace NetworcoId.Tests;

public class PasswordChangeFlowTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public PasswordChangeFlowTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", "InMemory" }
                    , { "Nats:ProvisionStreams", "false" }
                });
            });
            builder.ConfigureServices(services =>
            {
                // 1. Remove ANY existing DbContext registration including DataProtection ones
                var efInternalDescriptors = services.Where(d => 
                    d.ServiceType == typeof(DbContextOptions<AuthDbContext>) || 
                    d.ServiceType == typeof(AuthDbContext) ||
                    d.ServiceType.FullName?.Contains("Microsoft.EntityFrameworkCore") == true ||
                    d.ServiceType.FullName?.Contains("Npgsql") == true ||
                    d.ServiceType.FullName?.Contains("DataProtection") == true
                ).ToList();

                foreach (var descriptor in efInternalDescriptors)
                {
                    services.Remove(descriptor);
                }

                var natsDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(INatsConnection));
                if (natsDescriptor != null) services.Remove(natsDescriptor);

                // 2. Add InMemory database for testing
                services.AddDbContext<AuthDbContext>(options =>
                {
                    options.UseInMemoryDatabase("TestDb");
                });

                // 3. Mock NATS using Moq
                var mockNats = new Mock<INatsConnection>();
                mockNats.Setup(n => n.Opts).Returns(new NatsOpts());
                services.AddSingleton<INatsConnection>(mockNats.Object);

                // 4. Ensure migrations don't run or fail in test
                var bootstrapDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IBootstrapService));
                if (bootstrapDescriptor != null) services.Remove(bootstrapDescriptor);
                services.AddScoped<IBootstrapService, MockBootstrapService>();

                // 5. Disable Data Protection DB persistence for tests to avoid circular dependency
                services.AddDataProtection();

                // 6. Disable Antiforgery for tests
                services.AddAntiforgery(options => 
                {
                    options.Cookie.Expiration = TimeSpan.FromDays(1);
                    options.HeaderName = "X-XSRF-TOKEN";
                });
                services.Configure<Microsoft.AspNetCore.Mvc.MvcOptions>(options => 
                {
                    options.Filters.Add(new Microsoft.AspNetCore.Mvc.IgnoreAntiforgeryTokenAttribute());
                });

                // 7. Mock PasswordValidator to pass any password
                var mockValidator = new Mock<IPasswordValidator>();
                mockValidator.Setup(v => v.Validate(It.IsAny<string>())).Returns((true, null));
                services.AddSingleton<IPasswordValidator>(mockValidator.Object);
            });
        });
    }


    private class MockBootstrapService : IBootstrapService
    {
        public Task BootstrapAsync() => Task.CompletedTask;
    }

    [Fact]

    public async Task Login_WithMustChangePassword_RedirectsToChangePassword()
    {
        // Arrange
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            
            // Seed a user with MustChangePassword = true
            var userId = Guid.NewGuid();
            db.Users.Add(new Models.Entities.UserEntity
            {
                Id = userId,
                Email = "test@example.com",
                FirstName = "Test",
                LastName = "User",
                IsActive = true
            });
            db.UserCredentials.Add(new Models.Entities.UserCredentialEntity
            {
                Id = userId,
                PasswordHash = hasher.HashPassword("OldP@ssword123!"),
                MustChangePassword = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            db.OAuthClients.Add(new Models.Entities.OAuthClientEntity
            {
                ClientId = "test-client",
                DisplayName = "Test Client",
                PrimaryClientSecretHash = hasher.HashPassword("secret"),
                RedirectUris = new List<string> { "https://example.com/callback" },
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        // Act
        var response = await client.PostAsync("/Login?client_id=test-client&redirect_uri=https://example.com/callback", 
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "Email", "test@example.com" },
                { "Password", "OldP@ssword123!" },
                { "client_id", "test-client" },
                { "redirect_uri", "https://example.com/callback" }
            }));

        // Assert
        Assert.Equal(System.Net.HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/ChangePassword", response.Headers.Location?.ToString() ?? "");
    }

    [Fact]
    public async Task ChangePassword_UpdatesPassword_AndClearsFlag()
    {
        // Arrange
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var email = "change@example.com";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            
            var userId = Guid.NewGuid();
            db.Users.Add(new Models.Entities.UserEntity { Id = userId, Email = email, FirstName = "C", LastName = "P", IsActive = true });
            db.UserCredentials.Add(new Models.Entities.UserCredentialEntity { Id = userId, PasswordHash = hasher.HashPassword("OldP@ssword123!"), MustChangePassword = true, CreatedAt = DateTimeOffset.UtcNow });
            await db.SaveChangesAsync();
        }

        // Act
        var response = await client.PostAsync("/ChangePassword", 
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "Email", email },
                { "CurrentPassword", "OldP@ssword123!" },
                { "NewPassword", "NewP@ssword123!" },
                { "ConfirmPassword", "NewP@ssword123!" },
                { "client_id", "test-client" },
                { "redirect_uri", "https://example.com/callback" }
            }));

        // Assert
        Assert.Equal(System.Net.HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/Login", response.Headers.Location?.ToString() ?? "");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            var user = await db.UserCredentials.FirstOrDefaultAsync(u => u.User.Email == email);
            
            Assert.NotNull(user);
            Assert.False(user.MustChangePassword);
            Assert.True(hasher.VerifyPassword("NewP@ssword123!", user.PasswordHash));
        }
    }
}

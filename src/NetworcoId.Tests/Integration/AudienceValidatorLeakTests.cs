using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using Xunit;

namespace NetworcoId.Tests.Integration;

/// <summary>
/// The bearer AudienceValidator used to call services.BuildServiceProvider() per request,
/// leaking a whole DI container (plus a console-logger thread) each time — prod reached
/// 3,400 leaked containers in 37 days and test died OOM. A new container re-runs the
/// DbContext options callback, so counting those calls detects the leak.
/// </summary>
public class AudienceValidatorLeakTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private const string ClientAudience = "leak-test-audience";
    private const string InactiveAudience = "leak-test-inactive-audience";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string? _originalDbUrl;
    private int _optionsBuilds;

    public AudienceValidatorLeakTests(WebApplicationFactory<Program> factory)
    {
        _originalDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
        Environment.SetEnvironmentVariable("DATABASE_URL", "InMemory");
        var dbName = "AudienceLeakTestDb_" + Guid.NewGuid();

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
                    Interlocked.Increment(ref _optionsBuilds);
                    options.UseInMemoryDatabase(dbName);
                };
                services.AddDbContextFactory<AuthDbContext>(configureOptions, ServiceLifetime.Singleton);
                services.AddDbContext<AuthDbContext>(configureOptions, ServiceLifetime.Scoped, ServiceLifetime.Singleton);
            });
        });

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        db.OAuthClients.Add(new OAuthClientEntity
        {
            ClientId = "leak-test-client",
            Audience = ClientAudience,
            DisplayName = "Leak Test Client",
            PrimaryClientSecretHash = "unused",
            CreatedAt = DateTimeOffset.UtcNow
        });
        db.OAuthClients.Add(new OAuthClientEntity
        {
            ClientId = "leak-test-inactive-client",
            Audience = InactiveAudience,
            DisplayName = "Inactive Client",
            PrimaryClientSecretHash = "unused",
            IsActive = false,
            CreatedAt = DateTimeOffset.UtcNow
        });
        db.SaveChanges();
    }

    public void Dispose() => Environment.SetEnvironmentVariable("DATABASE_URL", _originalDbUrl);

    [Fact]
    public void AudienceValidator_does_not_build_a_container_per_call()
    {
        var parameters = _factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        var validate = parameters.AudienceValidator!;

        // Warm up so any one-time options builds are done before we count.
        Assert.True(validate(new[] { ClientAudience }, null!, parameters));
        var before = Volatile.Read(ref _optionsBuilds);

        for (var i = 0; i < 20; i++)
        {
            Assert.True(validate(new[] { ClientAudience }, null!, parameters));
            Assert.False(validate(new[] { "unknown-audience" }, null!, parameters));
        }

        Assert.Equal(before, Volatile.Read(ref _optionsBuilds));
    }

    [Fact]
    public void AudienceValidator_rejects_a_deactivated_clients_audience()
    {
        var parameters = _factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;

        Assert.False(parameters.AudienceValidator!(new[] { InactiveAudience }, null!, parameters));
        Assert.True(parameters.AudienceValidator!(new[] { "unknown", ClientAudience }, null!, parameters));
    }
}

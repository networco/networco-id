using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;

namespace NetworcoId.Configuration;


/// <summary>
/// Database configuration and service registration.
/// </summary>
public static class DatabaseConfiguration
{
    /// <summary>
    /// Adds PostgreSQL database services to the DI container.
    /// </summary>
    public static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection");

        if (string.IsNullOrEmpty(connectionString) || 
            connectionString == "PLACEHOLDER" ||
            string.Equals(connectionString, "InMemory", StringComparison.OrdinalIgnoreCase))
        {
             // If we are in a test context where "InMemory" is specified but not yet registered,
             // we should skip registration here and let the test fixture handle it.
             // If the test fixture already registered it, the check above (services.Any) would catch it.
             // But if we are here, and it is "InMemory", it likely means we shouldn't register Npgsql.
             if (string.Equals(connectionString, "InMemory", StringComparison.OrdinalIgnoreCase))
             {
                 return services;
             }
        }

        // Avoid duplicate registration if tests have already configured it
        if (services.Any(d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>)))
        {
            return services;
        }

        Action<DbContextOptionsBuilder> configureOptions = options =>
        {
            options.UseNpgsql(connectionString, npgsqlOptions =>
            {
                npgsqlOptions.EnableRetryOnFailure(3);
                npgsqlOptions.CommandTimeout(30);
            });

#if DEBUG
            options.EnableSensitiveDataLogging();
            options.EnableDetailedErrors();
#endif
        };

        // Register Factory as Singleton
        services.AddDbContextFactory<AuthDbContext>(configureOptions, ServiceLifetime.Singleton);

        // Register Scoped DbContext using the same options
        services.AddDbContext<AuthDbContext>(configureOptions, ServiceLifetime.Scoped, ServiceLifetime.Singleton);

        return services;
    }
}
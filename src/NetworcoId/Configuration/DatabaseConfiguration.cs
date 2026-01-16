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
    /// Uses EF Core with AsNoTracking by default for stateless API performance.
    /// </summary>
    public static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        if (services.Any(d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>)))
        {
            return services;
        }

        var connectionString = configuration.GetConnectionString("DefaultConnection");

        if (string.IsNullOrEmpty(connectionString) || connectionString == "PLACEHOLDER")
        {
            // If placeholder, try direct environment variables as fallback
            connectionString = Environment.GetEnvironmentVariable("DATABASE_URL");
        }

        if (string.Equals(connectionString, "InMemory", StringComparison.OrdinalIgnoreCase))
        {
            // Do NOT register anything here if InMemory is specified.
            // The caller (like a test) is responsible for registering the InMemory provider.
            return services;
        }

        // Allow overriding individual components via environment variables (common in Docker/K8s/Native Dev)
        var host = configuration["DATABASE_HOST"] ?? configuration["POSTGRES_HOST"] ?? configuration["DB_HOST"];
        var port = configuration["DATABASE_PORT"] ?? configuration["POSTGRES_PORT"] ?? configuration["DB_PORT"] ?? "5432";
        var database = configuration["DATABASE_NAME"] ?? configuration["POSTGRES_DB"] ?? configuration["DB_NAME"] ?? "networco_id";
        var user = configuration["DATABASE_USER"] ?? configuration["POSTGRES_USER"] ?? configuration["DB_USER"];
        var password = configuration["DATABASE_PASSWORD"] ?? configuration["POSTGRES_PASSWORD"] ?? configuration["DB_PASSWORD"];

        if (!string.IsNullOrEmpty(host) && !string.IsNullOrEmpty(user))
        {
            connectionString = $"Host={host};Port={port};Database={database};Username={user};Password={password};Ssl Mode=Prefer;";
        }

        if (string.IsNullOrEmpty(connectionString) || connectionString == "PLACEHOLDER")
        {
            throw new InvalidOperationException("Connection string is missing or is set to PLACEHOLDER. Check your .env file or environment variables.");
        }

        services.AddDbContext<AuthDbContext>(options =>
        {
            options.UseNpgsql(connectionString, npgsqlOptions =>
            {
                // Enable retry on failure for transient errors
                npgsqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 3,
                    maxRetryDelay: TimeSpan.FromSeconds(5),
                    errorCodesToAdd: null);

                // Command timeout
                npgsqlOptions.CommandTimeout(30);

                // Use default schema (public) for migrations history
                // npgsqlOptions.MigrationsHistoryTable("__EFMigrationsHistory", "auth");
            });

            // Development: Enable sensitive data logging and detailed errors
            #if DEBUG
            options.EnableSensitiveDataLogging();
            options.EnableDetailedErrors();
            #endif
        });

        return services;
    }
}
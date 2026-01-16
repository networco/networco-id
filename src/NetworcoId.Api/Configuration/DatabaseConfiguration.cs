using Microsoft.EntityFrameworkCore;
using Networco.Auth.Infrastructure.Database;

namespace Networco.Auth.Configuration;

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
        var connectionString = configuration.GetConnectionString("DefaultConnection");

        // Allow overriding individual components via environment variables (common in Docker/K8s/Native Dev)
        var host = configuration["DATABASE_HOST"] ?? configuration["POSTGRES_HOST"] ?? configuration["DB_HOST"];
        var port = configuration["DATABASE_PORT"] ?? configuration["POSTGRES_PORT"] ?? configuration["DB_PORT"] ?? "5432";
        var database = configuration["DATABASE_NAME"] ?? configuration["POSTGRES_DB"] ?? configuration["DB_NAME"] ?? "networco_auth";
        var user = configuration["DATABASE_USER"] ?? configuration["POSTGRES_USER"] ?? configuration["DB_USER"];
        var password = configuration["DATABASE_PASSWORD"] ?? configuration["POSTGRES_PASSWORD"] ?? configuration["DB_PASSWORD"];

        if (!string.IsNullOrEmpty(host) && !string.IsNullOrEmpty(user))
        {
            connectionString = $"Host={host};Port={port};Database={database};Username={user};Password={password};Ssl Mode=Prefer;";
        }

        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException("Connection string not found in configuration or environment variables.");
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

                // Use auth schema for migrations history
                npgsqlOptions.MigrationsHistoryTable("__EFMigrationsHistory", "auth");
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
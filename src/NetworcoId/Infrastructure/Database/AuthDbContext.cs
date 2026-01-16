using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using NetworcoId.Models.Entities;

namespace NetworcoId.Infrastructure.Database;

/// <summary>
/// Authentication service database context.
/// Contains all authentication-related data.
/// </summary>
public class AuthDbContext : DbContext, IDataProtectionKeyContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
        // Stateless API optimization: disable change tracking by default
        ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
    }

    // Authentication entities
    public DbSet<UserEntity> Users => Set<UserEntity>();
    public DbSet<UserCredentialEntity> UserCredentials => Set<UserCredentialEntity>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<AuthSessionEntity> AuthSessions => Set<AuthSessionEntity>();
    public DbSet<OAuthClientEntity> OAuthClients => Set<OAuthClientEntity>();
    public DbSet<AuditLogEntity> AuditLogs => Set<AuditLogEntity>();
    
    // Data Protection keys for multi-instance deployments
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Use "auth" schema for all authentication tables
        // modelBuilder.HasDefaultSchema("auth");

        // Configure OAuthClientEntity
        modelBuilder.Entity<OAuthClientEntity>(entity =>
        {
            entity.HasKey(e => e.ClientId);
            entity.Property(e => e.ClientId).HasMaxLength(100);
            entity.Property(e => e.DisplayName).HasMaxLength(200);
        });

        // Apply all configurations from this assembly
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);

        // Use snake_case naming convention for PostgreSQL
        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            // Table name: UserEntity -> users
            var tableName = ToSnakeCase(entity.GetTableName() ?? entity.ClrType.Name);
            if (tableName.EndsWith("_entity"))
            {
                tableName = tableName[..^7]; // Remove "_entity" suffix
            }
            entity.SetTableName(tableName);

            // Column names
            foreach (var property in entity.GetProperties())
            {
                property.SetColumnName(ToSnakeCase(property.Name));
            }
        }
    }

    private static string ToSnakeCase(string str)
    {
        return string.Concat(str.Select((c, i) =>
            i > 0 && char.IsUpper(c) ? "_" + char.ToLower(c) : char.ToLower(c).ToString()));
    }
}
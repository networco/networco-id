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
        // WARNING: This causes issues when multiple providers are registered in tests
        // or when using inheritance with different providers.
        // ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
    }

    // Authentication entities
    public DbSet<UserEntity> Users => Set<UserEntity>();
    public DbSet<UserCredentialEntity> UserCredentials => Set<UserCredentialEntity>();
    public DbSet<UserExternalLoginEntity> UserExternalLogins => Set<UserExternalLoginEntity>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<AuthSessionEntity> AuthSessions => Set<AuthSessionEntity>();
    public DbSet<OAuthClientEntity> OAuthClients => Set<OAuthClientEntity>();
    public DbSet<AuditLogEntity> AuditLogs => Set<AuditLogEntity>();
    public DbSet<SigningKeyEntity> SigningKeys => Set<SigningKeyEntity>();
    public DbSet<SystemSettingEntity> SystemSettings => Set<SystemSettingEntity>();
    public DbSet<IpLockoutEntity> IpLockouts => Set<IpLockoutEntity>();
    
    // Data Protection keys for multi-instance deployments
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure SystemSettingEntity
        modelBuilder.Entity<SystemSettingEntity>(entity =>
        {
            entity.HasKey(e => e.Key);
            entity.Property(e => e.Key).HasMaxLength(100);
            entity.Property(e => e.Value).HasMaxLength(1000);
        });

        // Use "auth" schema for all authentication tables
        // modelBuilder.HasDefaultSchema("auth");

        // Configure OAuthClientEntity
        modelBuilder.Entity<OAuthClientEntity>(entity =>
        {
            entity.HasKey(e => e.ClientId);
            entity.Property(e => e.ClientId).HasMaxLength(100);
            entity.Property(e => e.DisplayName).HasMaxLength(200);
        });

        // Configure SigningKeyEntity
        modelBuilder.Entity<SigningKeyEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.KeyId).IsUnique();
            entity.Property(e => e.KeyId).HasMaxLength(100);
            entity.Property(e => e.Algorithm).HasMaxLength(20);
            entity.Property(e => e.Status).HasConversion<string>();
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

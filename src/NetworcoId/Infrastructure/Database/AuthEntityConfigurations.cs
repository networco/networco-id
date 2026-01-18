using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using NetworcoId.Models.Entities;

namespace NetworcoId.Infrastructure.Database;

/// <summary>
/// EF Core configuration for UserEntity.
/// </summary>
public class UserEntityConfiguration : IEntityTypeConfiguration<UserEntity>
{
    public void Configure(EntityTypeBuilder<UserEntity> builder)
    {
        builder.HasKey(u => u.Id);

        builder.Property(u => u.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(u => u.Email)
            .HasMaxLength(255)
            .IsRequired();

        builder.HasIndex(u => u.Email)
            .IsUnique();

        builder.Property(u => u.FirstName)
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(u => u.LastName)
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(u => u.Roles)
            .HasColumnType("text[]");

        builder.Property(u => u.NationalId)
            .HasMaxLength(11); // Norwegian fødselsnummer format

        builder.Property(u => u.PhoneNumber)
            .HasMaxLength(20);

        builder.Property(u => u.CreatedAt)
            .HasDefaultValueSql("now()");

        builder.Property(u => u.IsActive)
            .HasDefaultValue(true);

        // 1:1 relationship with credentials
        builder.HasOne(u => u.Credential)
            .WithOne(c => c.User)
            .HasForeignKey<UserCredentialEntity>(c => c.Id)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

/// <summary>
/// EF Core configuration for UserCredentialEntity.
/// </summary>
public class UserCredentialEntityConfiguration : IEntityTypeConfiguration<UserCredentialEntity>
{
    public void Configure(EntityTypeBuilder<UserCredentialEntity> builder)
    {
        builder.HasKey(c => c.Id);

        // 1:1 relationship - Id is same as user Id
        builder.Property(c => c.PasswordHash)
            .HasMaxLength(255)
            .IsRequired();

        builder.Property(c => c.CreatedAt)
            .HasDefaultValueSql("now()");

        builder.Property(c => c.FailedLoginAttempts)
            .HasDefaultValue(0);

        // Index for performance
        builder.HasIndex(c => c.Id);
    }
}

/// <summary>
/// EF Core configuration for RefreshTokenEntity.
/// </summary>
public class RefreshTokenEntityConfiguration : IEntityTypeConfiguration<RefreshTokenEntity>
{
    public void Configure(EntityTypeBuilder<RefreshTokenEntity> builder)
    {
        builder.HasKey(t => t.Id);

        builder.Property(t => t.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(t => t.TokenHash)
            .HasMaxLength(64)
            .IsRequired();

        builder.HasIndex(t => t.TokenHash)
            .IsUnique();

        builder.Property(t => t.CreatedAt)
            .HasDefaultValueSql("now()");

        builder.HasIndex(t => new { t.UserId, t.RevokedAt })
            .HasFilter("revoked_at IS NULL");

        builder.HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

/// <summary>
/// EF Core configuration for AuthSessionEntity.
/// </summary>
public class AuthSessionEntityConfiguration : IEntityTypeConfiguration<AuthSessionEntity>
{
    public void Configure(EntityTypeBuilder<AuthSessionEntity> builder)
    {
        builder.HasKey(s => s.Id);

        builder.Property(s => s.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(s => s.SessionId)
            .HasMaxLength(128)
            .IsRequired();

        builder.HasIndex(s => s.SessionId)
            .IsUnique();

        builder.Property(s => s.IpAddress)
            .HasMaxLength(45) // IPv6 length
            .IsRequired();

        builder.Property(s => s.UserAgent)
            .HasMaxLength(500);

        builder.Property(s => s.CreatedAt)
            .HasDefaultValueSql("now()");

        builder.Property(s => s.IsActive)
            .HasDefaultValue(true);

        builder.HasIndex(s => new { s.UserId, s.IsActive });

        builder.HasOne(s => s.User)
            .WithMany()
            .HasForeignKey(s => s.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

/// <summary>
/// EF Core configuration for AuditLogEntity.
/// </summary>
public class AuditLogEntityConfiguration : IEntityTypeConfiguration<AuditLogEntity>
{
    public void Configure(EntityTypeBuilder<AuditLogEntity> builder)
    {
        builder.HasKey(a => a.Id);

        builder.Property(a => a.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(a => a.EventType)
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(a => a.Description)
            .HasMaxLength(1000)
            .IsRequired();

        builder.Property(a => a.IpAddress)
            .HasMaxLength(45);

        builder.Property(a => a.UserAgent)
            .HasMaxLength(500);

        builder.Property(a => a.Timestamp)
            .HasDefaultValueSql("now()");

        builder.Property(a => a.Metadata)
            .HasColumnType("jsonb");

        builder.HasOne(a => a.User)
            .WithMany()
            .HasForeignKey(a => a.UserId)
            .OnDelete(DeleteBehavior.SetNull);

        builder.HasIndex(a => a.EventType);
        builder.HasIndex(a => a.Timestamp);
    }
}
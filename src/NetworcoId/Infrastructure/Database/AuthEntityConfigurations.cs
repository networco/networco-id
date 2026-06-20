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

        builder.Property(u => u.BirthDate)
            .HasMaxLength(10); // OIDC birthdate "YYYY-MM-DD"

        // 1:1 relationship with credentials
        builder.HasOne(u => u.Credential)
            .WithOne(c => c.User)
            .HasForeignKey<UserCredentialEntity>(c => c.Id)
            .OnDelete(DeleteBehavior.Cascade);

        // 1:many external logins
        builder.HasMany(u => u.ExternalLogins)
            .WithOne(e => e.User)
            .HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

/// <summary>
/// EF Core configuration for UserExternalLoginEntity.
/// </summary>
public class UserExternalLoginEntityConfiguration : IEntityTypeConfiguration<UserExternalLoginEntity>
{
    public void Configure(EntityTypeBuilder<UserExternalLoginEntity> builder)
    {
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id)
            .HasDefaultValueSql("gen_random_uuid()");

        builder.Property(e => e.Provider)
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(e => e.Subject)
            .HasMaxLength(255)
            .IsRequired();

        builder.Property(e => e.CreatedAt)
            .HasDefaultValueSql("now()");

        // A given external identity (provider, subject) may be linked to MORE THAN ONE
        // local account — a real person can legitimately hold several accounts (e.g. a
        // personal candidate account and being a contact on an employer), distinguished
        // by email. At BankID login we present an account picker when a subject resolves
        // to multiple accounts. We still forbid linking the same identity to the same
        // account twice, hence the uniqueness on (Provider, Subject, UserId).
        builder.HasIndex(e => new { e.Provider, e.Subject, e.UserId })
            .IsUnique();
        // Non-unique lookup index for resolving all accounts for a subject at login.
        builder.HasIndex(e => new { e.Provider, e.Subject });
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

/// <summary>
/// EF Core configuration for IpLockoutEntity.
/// </summary>
public class IpLockoutEntityConfiguration : IEntityTypeConfiguration<IpLockoutEntity>
{
    public void Configure(EntityTypeBuilder<IpLockoutEntity> builder)
    {
        builder.HasKey(l => l.IpAddress);

        builder.Property(l => l.IpAddress)
            .HasMaxLength(45); // IPv6 length

        builder.Property(l => l.FailedAttempts)
            .HasDefaultValue(0);

        builder.Property(l => l.LastAttemptAt)
            .HasDefaultValueSql("now()");

        builder.HasIndex(l => l.LockedUntil);
    }
}

/// <summary>
/// EF Core configuration for OAuthClientEntity.
/// </summary>
public class OAuthClientEntityConfiguration : IEntityTypeConfiguration<OAuthClientEntity>
{
    public void Configure(EntityTypeBuilder<OAuthClientEntity> builder)
    {
        builder.HasKey(c => c.ClientId);

        builder.Property(c => c.ClientId)
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(c => c.Audience)
            .HasMaxLength(255)
            .IsRequired();

        builder.Property(c => c.PrimaryClientSecretHash)
            .HasMaxLength(255)
            .IsRequired();

        builder.Property(c => c.SecondaryClientSecretHash)
            .HasMaxLength(255);

        builder.Property(c => c.DisplayName)
            .HasMaxLength(255)
            .IsRequired();

        builder.Property(c => c.CreatedAt)
            .HasDefaultValueSql("now()");

        builder.Property(c => c.IsActive)
            .HasDefaultValue(true);

        builder.Property(c => c.IsDefault)
            .HasDefaultValue(false);

        // Partial unique index — at most one client can hold the default flag.
        // The service layer also clears any prior default before saving, but
        // this is the hard guarantee.
        builder.HasIndex(c => c.IsDefault)
            .IsUnique()
            .HasFilter("is_default = true");
    }
}

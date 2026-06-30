namespace NetworcoId.Models.Entities;

/// <summary>
/// User entity.
/// Contains user identity information for authentication.
/// </summary>
public class UserEntity
{
    public Guid Id { get; set; }
    public required string Email { get; set; }
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
    public List<string> Roles { get; set; } = new();
    public string? NationalId { get; set; } // Mock fødselsnummer for testing
    public string? PhoneNumber { get; set; }
    
    // Address (OIDC Standard Claims)
    public string? AddressFormatted { get; set; }
    public string? AddressStreetAddress { get; set; }
    public string? AddressLocality { get; set; }
    public string? AddressRegion { get; set; }
    public string? AddressPostalCode { get; set; }
    public string? AddressCountry { get; set; }
    
    // Email verification
    public string? EmailVerificationToken { get; set; }
    public DateTimeOffset? EmailVerificationTokenExpiresAt { get; set; }
    public bool EmailVerified { get; set; } = false;
    /// <summary>
    /// Identifier shared with an HttpOnly cookie set on the registering browser.
    /// The verify endpoint only auto-logs the user in when the cookie matches —
    /// if the link is opened on a different browser/device (e.g. an attacker who
    /// intercepted the email) the cookie is absent and the user is forced to log
    /// in with their password instead.
    /// </summary>
    public string? EmailVerificationSessionId { get; set; }
    
    // Password reset
    public string? PasswordResetToken { get; set; }
    public DateTimeOffset? PasswordResetTokenExpiresAt { get; set; }
    
    // Phone verification
    public bool PhoneNumberVerified { get; set; } = false;

    // OIDC birthdate claim (YYYY-MM-DD), e.g. from BankID via IDura.
    public string? BirthDate { get; set; }

    // One-time ticket for the "connect BankID" (verify-to-link) step-up flow. Minted by
    // an access-token-authenticated start request and consumed when the browser reaches
    // /auth/external/link, so we know which account to attach the BankID identity to
    // without relying on the (possibly expired) NETWORCO ID session.
    public string? BankIdLinkToken { get; set; }
    public DateTimeOffset? BankIdLinkTokenExpiresAt { get; set; }

    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }

    // Navigation property
    public UserCredentialEntity? Credential { get; set; }

    // External federated logins (e.g. IDura/BankID). A user may have none
    // (password-only) or several (one per provider).
    public List<UserExternalLoginEntity> ExternalLogins { get; set; } = new();
}

/// <summary>
/// Links a local user to an identity at an external OIDC provider (e.g. IDura,
/// which brokers Norwegian BankID). Keyed by (Provider, Subject).
/// </summary>
public class UserExternalLoginEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    /// <summary>Provider key, e.g. "idura".</summary>
    public required string Provider { get; set; }
    /// <summary>The provider's stable subject identifier (the OIDC `sub`).</summary>
    public required string Subject { get; set; }
    /// <summary>Given name as asserted by the provider (BankID legal name), if any.</summary>
    public string? FirstName { get; set; }
    /// <summary>Family name as asserted by the provider (BankID legal name), if any.</summary>
    public string? LastName { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }

    // Navigation property
    public UserEntity User { get; set; } = null!;
}

/// <summary>
/// User credentials entity.
/// Contains password hashes and auth secrets.
/// Separated for security and data minimization.
/// </summary>
public class UserCredentialEntity
{
    public Guid Id { get; set; } // Same as UserEntity.Id (1:1 relationship)
    public required string PasswordHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
    public bool MustChangePassword { get; set; } = false;
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTimeOffset? LastFailedLoginAt { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }

    // Navigation property
    public UserEntity User { get; set; } = null!;
}

/// <summary>
/// Refresh token entity for JWT refresh tokens.
/// </summary>
public class RefreshTokenEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string? ClientId { get; set; } // Added for client binding
    public required string TokenHash { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? ReplacedByTokenId { get; set; }

    // Navigation property
    public UserEntity User { get; set; } = null!;
}

/// <summary>
/// Authentication session entity.
/// Tracks active authentication sessions.
/// </summary>
public class AuthSessionEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public required string SessionId { get; set; }
    public required string IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public bool IsActive { get; set; } = true;

    // Navigation property
    public UserEntity User { get; set; } = null!;
}

/// <summary>
/// Audit log entity for tracking system events.
/// </summary>
public class AuditLogEntity
{
    public Guid Id { get; set; }
    public Guid? UserId { get; set; }
    public required string EventType { get; set; } // e.g., Login, PasswordChange, AccountCreated
    public required string Description { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public required DateTimeOffset Timestamp { get; set; }
    public string? Metadata { get; set; } // JSON blob for additional info

    // Navigation property
    public UserEntity? User { get; set; }
}
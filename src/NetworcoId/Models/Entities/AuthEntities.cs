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
    // Removed: RoleId - authorization handled by resource server
    public string? NationalId { get; set; } // Mock fødselsnummer for testing
    public string? PhoneNumber { get; set; }
    
    // Email verification
    public string? EmailVerificationToken { get; set; }
    public DateTimeOffset? EmailVerificationTokenExpiresAt { get; set; }
    public bool EmailVerified { get; set; } = false;
    
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }

    // Navigation property
    public UserCredentialEntity? Credential { get; set; }
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
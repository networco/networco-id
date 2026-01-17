namespace NetworcoId.Models.Entities;

/// <summary>
/// Entity for storing RSA signing keys for JWKS rotation.
/// </summary>
public class SigningKeyEntity
{
    public Guid Id { get; set; }
    
    /// <summary>
    /// Key ID (kid) exposed in the JWKS.
    /// </summary>
    public required string KeyId { get; set; }
    
    /// <summary>
    /// Algorithm (e.g., RS256).
    /// </summary>
    public string Algorithm { get; set; } = "RS256";
    
    /// <summary>
    /// Private key in PEM format.
    /// Encrypted at rest by database encryption if available, but here stored as text.
    /// </summary>
    public required string PrivateKeyPem { get; set; }
    
    /// <summary>
    /// Public key in PEM format.
    /// </summary>
    public required string PublicKeyPem { get; set; }
    
    /// <summary>
    /// When the key was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }
    
    /// <summary>
    /// When the key should be rotated (stopped being used for new tokens).
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }
    
    /// <summary>
    /// Whether the key has been manually revoked.
    /// </summary>
    public bool IsRevoked { get; set; } = false;

    /// <summary>
    /// Status of the key: Active (signing), Previous (validation only), Retired (neither).
    /// </summary>
    public KeyStatus Status { get; set; }
}

public enum KeyStatus
{
    Active,
    Previous,
    Retired
}

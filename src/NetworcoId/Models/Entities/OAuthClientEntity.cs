namespace NetworcoId.Models.Entities;

/// <summary>
/// OAuth2 Client entity.
/// Represents an application allowed to use the identity provider.
/// </summary>
public class OAuthClientEntity
{
    public required string ClientId { get; set; }
    public required string Audience { get; set; }
    public required string PrimaryClientSecretHash { get; set; }
    public string? SecondaryClientSecretHash { get; set; }
    public required string DisplayName { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public List<string> AllowedScopes { get; set; } = new();
    public bool IsTrustedForExchange { get; set; } = false;
    public bool IsActive { get; set; } = true;
    /// <summary>
    /// Marks this client as the default fallback when /Login is hit without
    /// OAuth params (e.g. someone bookmarked the bare login page). At most one
    /// active client may carry this flag — enforced by a partial unique index.
    /// </summary>
    public bool IsDefault { get; set; } = false;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}

namespace Networco.Auth.Models.Entities;

/// <summary>
/// OAuth2 Client entity.
/// Represents an application allowed to use the identity provider.
/// </summary>
public class OAuthClientEntity
{
    public required string ClientId { get; set; }
    public required string PrimaryClientSecretHash { get; set; }
    public string? SecondaryClientSecretHash { get; set; }
    public required string DisplayName { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public List<string> AllowedScopes { get; set; } = new();
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}

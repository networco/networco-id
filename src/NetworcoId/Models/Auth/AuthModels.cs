using NetworcoId.Core.Models;

namespace NetworcoId.Models.Auth;

/// <summary>
/// NETWORCO ID authentication configuration.
/// </summary>
public class NetworcoIdConfig
{
    public bool Enabled { get; set; } = true;
    public string? Secret { get; set; } // Legacy - preferred is Auth:Jwt:SigningKey
    public string? SigningKey { get; set; } // Combined from Auth:Jwt:SigningKey
    public int AccessTokenExpirationMinutes { get; set; } = 15;
    public int RefreshTokenExpirationDays { get; set; } = 7;
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public string BaseUrl { get; set; } = "http://localhost:5200";
    
    // Initial Bootstrap Configuration
    public string? InitialAdminEmail { get; set; }
    public string? InitialAdminPassword { get; set; }
    public string? InitialClientId { get; set; }
    public string? InitialClientSecret { get; set; }

    public List<NetworcoIdUserDto> TestUsers { get; set; } = new();

    // JWKS / Signing Configuration
    public string? JwksJson { get; set; }
    public string? SigningKeyPem { get; set; } // RS256 Private Key
    public string? SigningKeyId { get; set; } = "networco-id-primary";

    // Security Settings
    public int MinPasswordLength { get; set; } = 12;
    public bool RequireDigit { get; set; } = true;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireNonAlphanumeric { get; set; } = true;
    public int MaxFailedLoginAttempts { get; set; } = 5;
    public int LockoutDurationMinutes { get; set; } = 15;
}

/// <summary>
/// NETWORCO ID user for authentication (DTO).
/// Contains only identity information, no roles.
/// </summary>
public class NetworcoIdUserDto
{
    public required Guid Id { get; set; }
    public required string NationalId { get; set; }
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
    public required string Email { get; set; }
    public string? PhoneNumber { get; set; }
    public string? Password { get; set; }
    public bool MustChangePassword { get; set; }
}

/// <summary>
/// Authentication request.
/// </summary>
public class AuthenticateRequest
{
    public required string EmailOrNationalId { get; set; }
    public required string Password { get; set; }
}

/// <summary>
/// User registration request.
/// </summary>
public class RegisterRequest
{
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
    public string? NationalId { get; set; }
    public string? PhoneNumber { get; set; }
}

/// <summary>
/// Authentication response.
/// </summary>
public class AuthenticateResponse
{
    public required string AccessToken { get; set; }
    public required string RefreshToken { get; set; }
    public required int ExpiresIn { get; set; }
    public required string TokenType { get; set; } = "Bearer";
    public required NetworcoIdUserDto User { get; set; }
}

/// <summary>
/// Refresh token request.
/// </summary>
public class RefreshTokenRequest
{
    public required string RefreshToken { get; set; }
}

/// <summary>
/// Refresh token response.
/// </summary>
public class RefreshTokenResponse
{
    public required string AccessToken { get; set; }
    public required string RefreshToken { get; set; }
    public required int ExpiresIn { get; set; }
    public required string TokenType { get; set; } = "Bearer";
    public required NetworcoIdUserDto User { get; set; }
}

/// <summary>
/// OAuth2 authorization request.
/// </summary>
public class AuthorizationRequest
{
    public required string ResponseType { get; set; }
    public required string ClientId { get; set; }
    public string? RedirectUri { get; set; }
    public string? State { get; set; }
    public string? Scope { get; set; }
}

/// <summary>
/// OAuth2 authorization response.
/// </summary>
public class AuthorizationResponse
{
    public required string Code { get; set; }
    public string? State { get; set; }
}

/// <summary>
/// OAuth2 client configuration.
/// </summary>
public class OAuthClient
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public string? SecondaryClientSecret { get; set; }
    public required string Name { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public List<string> AllowedScopes { get; set; } = new();
    public bool IsTrustedForExchange { get; set; }
}

/// <summary>
/// OAuth2 token request.
/// </summary>
public class TokenRequest
{
    public required string GrantType { get; set; }
    public required string Code { get; set; }
    public required string RedirectUri { get; set; }
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
}

/// <summary>
/// OAuth2 token response.
/// </summary>
public class TokenResponse
{
    public required string AccessToken { get; set; }
    public required string TokenType { get; set; } = "Bearer";
    public required int ExpiresIn { get; set; }
    public string? RefreshToken { get; set; }
    public string? Scope { get; set; }
}


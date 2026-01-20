using System.Text.Json.Serialization;
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

    // Data Protection
    public string? DataProtectionCertificatePath { get; set; }
    public string? DataProtectionCertificatePassword { get; set; }

    // Runtime tracked system client ID
    public string? SystemManagementClientId { get; set; }
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
    public List<string> Roles { get; set; } = new();
    public required string Email { get; set; }
    public string? PhoneNumber { get; set; }
    public string? Password { get; set; }
    public bool MustChangePassword { get; set; }
    public string? Nonce { get; set; }
    
    // Verification status
    public bool EmailVerified { get; set; }
    public bool PhoneNumberVerified { get; set; }
    
    // Address (OIDC Standard Claims)
    public string? AddressFormatted { get; set; }
    public string? AddressStreetAddress { get; set; }
    public string? AddressLocality { get; set; }
    public string? AddressRegion { get; set; }
    public string? AddressPostalCode { get; set; }
    public string? AddressCountry { get; set; }
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
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; set; }
    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; set; }
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; set; }
    [JsonPropertyName("token_type")]
    public required string TokenType { get; set; } = "Bearer";
    public required NetworcoIdUserDto User { get; set; }
}

/// <summary>
/// Refresh token request.
/// </summary>
public class RefreshTokenRequest
{
    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; set; }
}

/// <summary>
/// Refresh token response.
/// </summary>
public class RefreshTokenResponse
{
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; set; }
    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; set; }
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; set; }
    [JsonPropertyName("token_type")]
    public required string TokenType { get; set; } = "Bearer";
    public required NetworcoIdUserDto User { get; set; }
}

/// <summary>
/// Password reset request.
/// </summary>
public class ForgotPasswordRequest
{
    public required string Email { get; set; }
}

/// <summary>
/// Password reset completion request.
/// </summary>
public class ResetPasswordRequest
{
    public required string Token { get; set; }
    public required string NewPassword { get; set; }
}

/// <summary>
/// OAuth2 authorization request.
/// </summary>
public class AuthorizationRequest
{
    public required string ResponseType { get; set; }
    [JsonPropertyName("client_id")]
    public required string ClientId { get; set; }
    [JsonPropertyName("client_secret")]
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
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; set; }
    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }
    [JsonPropertyName("token_type")]
    public required string TokenType { get; set; } = "Bearer";
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; set; }
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
}


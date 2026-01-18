using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NetworcoId.Models.Auth;
using NetworcoId.Core.Models;
using NetworcoId.Models.Entities;
using NetworcoId.Infrastructure.Database;
using Microsoft.Extensions.Caching.Memory;
using NATS.Client.Core;

namespace NetworcoId.Infrastructure.Auth;

/// <summary>
/// JWT token service.
/// </summary>
public interface IJwtService
{
    Task<string> GenerateAccessTokenAsync(NetworcoIdUserDto user, IEnumerable<string>? scopes = null, CancellationToken cancellationToken = default);
    Task<string> GenerateIdTokenAsync(NetworcoIdUserDto user, string clientId, string? nonce = null, DateTimeOffset? authTime = null, CancellationToken cancellationToken = default);
    string GenerateRefreshToken();
    Task<ClaimsPrincipal?> ValidateTokenAsync(string token, CancellationToken cancellationToken = default);
    Task<JsonWebKeySet> GetPublicKeysAsync(CancellationToken cancellationToken = default);
    Task ListenForKeyRotationEventsAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// JWT token service implementation with JWKS rotation support.
/// </summary>
public class JwtService : IJwtService
{
    private readonly NetworcoIdConfig _config;
    private readonly IKeyManagementService _keyManagementService;
    private readonly IMemoryCache _cache;
    private readonly INatsConnection _nats;
    private readonly ILogger<JwtService> _logger;
    
    private const string ValidKeysCacheKey = "valid_signing_keys";

    public JwtService(
        NetworcoIdConfig config,
        IKeyManagementService keyManagementService,
        IMemoryCache cache,
        INatsConnection nats,
        ILogger<JwtService> logger)
    {
        _config = config;
        _keyManagementService = keyManagementService;
        _cache = cache;
        _nats = nats;
        _logger = logger;
    }

    private async Task<List<SigningKeyEntity>> GetCachedKeysAsync(CancellationToken cancellationToken)
    {
        return await _cache.GetOrCreateAsync(ValidKeysCacheKey, async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10); // Cache for 10 mins
            return await _keyManagementService.GetValidKeysAsync(cancellationToken);
        }) ?? new List<SigningKeyEntity>();
    }

    public async Task ListenForKeyRotationEventsAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting listener for key rotation events...");
        
        // Subscribe to the rotation event subject
        await foreach (var msg in _nats.SubscribeAsync<object>(NetworcoIdSubjects.IdentityKeysRotated, cancellationToken: cancellationToken))
        {
            try
            {
                _logger.LogInformation("Received key rotation event. Invalidating local cache.");
                
                // 1. Remove the existing cache entry
                _cache.Remove(ValidKeysCacheKey);
                
                // 2. Immediately refresh the cache to ensure we have the new keys ready
                await GetCachedKeysAsync(cancellationToken);
                
                _logger.LogInformation("Local key cache refreshed successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling key rotation event.");
            }
        }
    }

    public async Task<string> GenerateIdTokenAsync(NetworcoIdUserDto user, string clientId, string? nonce = null, DateTimeOffset? authTime = null, CancellationToken cancellationToken = default)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            // ID Token specific claims
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.AuthTime, (authTime ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (!string.IsNullOrEmpty(nonce)) claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
        else if (!string.IsNullOrEmpty(user.Nonce)) claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, user.Nonce));

        var keys = await GetCachedKeysAsync(cancellationToken);
        var activeKeyEntity = keys.FirstOrDefault(k => k.Status == KeyStatus.Active) 
                              ?? keys.FirstOrDefault();

        SigningCredentials creds;
        if (activeKeyEntity != null)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(activeKeyEntity.PrivateKeyPem);
            var securityKey = new RsaSecurityKey(rsa) { KeyId = activeKeyEntity.KeyId };
            creds = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
        }
        else
        {
            var signingKey = _config.Secret 
                ?? throw new InvalidOperationException("No signing keys found.");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        }

        var token = new JwtSecurityToken(
            issuer: _config.Issuer,
            audience: clientId, // ID Token audience IS the client_id
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_config.AccessTokenExpirationMinutes), // ID token usually short lived, same as access token here
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<string> GenerateAccessTokenAsync(NetworcoIdUserDto user, IEnumerable<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        
        // Scope handling
        var scopeList = scopes?.ToList() ?? new List<string>();
        if (scopeList.Any())
        {
            claims.Add(new Claim("scope", string.Join(" ", scopeList)));
        }

        // Email claim - only if 'email' scope is requested
        if (scopeList.Contains("email"))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim("email_verified", user.EmailVerified.ToString().ToLower(), ClaimValueTypes.Boolean));
        }

        // Profile claims - only if 'profile' scope is requested
        if (scopeList.Contains("profile"))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName));
            claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName));
            claims.Add(new Claim("name", $"{user.FirstName} {user.LastName}"));
            claims.Add(new Claim("preferred_username", user.Email));
            claims.Add(new Claim("updated_at", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));
            
            if (!string.IsNullOrEmpty(user.NationalId))
            {
                claims.Add(new Claim("national_id", user.NationalId));
            }
        }

        if (!string.IsNullOrEmpty(user.PhoneNumber) && scopeList.Contains("phone"))
        {
            claims.Add(new Claim("phone_number", user.PhoneNumber));
            claims.Add(new Claim("phone_number_verified", user.PhoneNumberVerified.ToString().ToLower(), ClaimValueTypes.Boolean));
        }

        if (scopeList.Contains("address"))
        {
             // OIDC spec requires address to be a JSON object.
             // We now have address fields on the user entity, so we can construct a proper object.
             var address = new 
             {
                 formatted = user.AddressFormatted ?? "",
                 street_address = user.AddressStreetAddress ?? "",
                 locality = user.AddressLocality ?? "",
                 region = user.AddressRegion ?? "",
                 postal_code = user.AddressPostalCode ?? "",
                 country = user.AddressCountry ?? ""
             };
             
             // Serialize to JSON string for the claim
             claims.Add(new Claim("address", System.Text.Json.JsonSerializer.Serialize(address), "json"));
        }

        var keys = await GetCachedKeysAsync(cancellationToken);
        var activeKeyEntity = keys.FirstOrDefault(k => k.Status == KeyStatus.Active) 
                              ?? keys.FirstOrDefault(); // Fallback to any key if active missing (shouldn't happen)

        SigningCredentials creds;

        if (activeKeyEntity != null)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(activeKeyEntity.PrivateKeyPem);
            var securityKey = new RsaSecurityKey(rsa) { KeyId = activeKeyEntity.KeyId };
            creds = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
        }
        else
        {
            // Fallback to static config secret (only if DB keys are missing entirely)
            var signingKey = _config.Secret 
                ?? throw new InvalidOperationException("No signing keys found in DB and no static secret configured.");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        }

        var token = new JwtSecurityToken(
            issuer: _config.Issuer,
            audience: _config.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_config.AccessTokenExpirationMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<JsonWebKeySet> GetPublicKeysAsync(CancellationToken cancellationToken = default)
    {
        var keys = await GetCachedKeysAsync(cancellationToken);
        var jwks = new JsonWebKeySet();

        foreach (var keyEntity in keys)
        {
            try 
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(keyEntity.PublicKeyPem);
                var securityKey = new RsaSecurityKey(rsa) { KeyId = keyEntity.KeyId };
                var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
                jwk.Use = "sig";
                jwk.Alg = !string.IsNullOrEmpty(keyEntity.Algorithm) ? keyEntity.Algorithm : "RS256";
                jwk.Kid = keyEntity.KeyId;
                jwks.Keys.Add(jwk);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error converting key {keyEntity.KeyId} to JWK: {ex.Message}");
            }
        }

        return jwks;
    }

    public string GenerateRefreshToken()
    {
        var randomBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var keys = await GetCachedKeysAsync(cancellationToken);
        
        var securityKeys = new List<SecurityKey>();

        // Add RSA keys
        foreach (var keyEntity in keys)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(keyEntity.PublicKeyPem);
            securityKeys.Add(new RsaSecurityKey(rsa) { KeyId = keyEntity.KeyId });
        }

        // Add static secret fallback
        if (!string.IsNullOrEmpty(_config.Secret))
        {
            securityKeys.Add(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.Secret)));
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = securityKeys, // Supports multiple keys
            ValidateIssuer = true,
            ValidIssuer = _config.Issuer,
            ValidateAudience = true,
            ValidAudience = _config.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        // ValidateToken is synchronous but we wrapped it in async flow
        var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
        return principal;
    }
}

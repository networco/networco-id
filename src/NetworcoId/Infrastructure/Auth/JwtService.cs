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

namespace NetworcoId.Infrastructure.Auth;

/// <summary>
/// JWT token service.
/// </summary>
public interface IJwtService
{
    Task<string> GenerateAccessTokenAsync(NetworcoIdUserDto user, CancellationToken cancellationToken = default);
    string GenerateRefreshToken();
    Task<ClaimsPrincipal?> ValidateTokenAsync(string token, CancellationToken cancellationToken = default);
    Task<JsonWebKeySet> GetPublicKeysAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// JWT token service implementation with JWKS rotation support.
/// </summary>
public class JwtService : IJwtService
{
    private readonly NetworcoIdConfig _config;
    private readonly IKeyManagementService _keyManagementService;
    private readonly IMemoryCache _cache;
    
    private const string ValidKeysCacheKey = "valid_signing_keys";

    public JwtService(
        NetworcoIdConfig config,
        IKeyManagementService keyManagementService,
        IMemoryCache cache)
    {
        _config = config;
        _keyManagementService = keyManagementService;
        _cache = cache;
    }

    private async Task<List<SigningKeyEntity>> GetCachedKeysAsync(CancellationToken cancellationToken)
    {
        return await _cache.GetOrCreateAsync(ValidKeysCacheKey, async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10); // Cache for 10 mins
            return await _keyManagementService.GetValidKeysAsync(cancellationToken);
        }) ?? new List<SigningKeyEntity>();
    }

    public async Task<string> GenerateAccessTokenAsync(NetworcoIdUserDto user, CancellationToken cancellationToken = default)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName),
            new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName),
            new Claim("national_id", user.NationalId ?? ""),
            new Claim("phone_number", user.PhoneNumber ?? ""),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

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
                jwk.Alg = keyEntity.Algorithm;
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

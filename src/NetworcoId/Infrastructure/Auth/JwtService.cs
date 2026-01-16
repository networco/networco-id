using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NetworcoId.Models.Auth;
using NetworcoId.Core.Models;
using System.Text.Json;

namespace NetworcoId.Infrastructure.Auth;

/// <summary>
/// JWT token service.
/// </summary>
public interface IJwtService
{
    string GenerateAccessToken(NetworcoIdUserDto user);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
    JsonWebKeySet GetPublicKeys();
}

/// <summary>
/// JWT token service implementation.
/// </summary>
public class JwtService : IJwtService
{
    private readonly NetworcoIdConfig _config;
    private readonly RsaSecurityKey? _rsaKey;
    private readonly string _kid;

    public JwtService(NetworcoIdConfig config)
    {
        _config = config;
        _kid = _config.SigningKeyId ?? "networco-id-primary";

        if (!string.IsNullOrEmpty(_config.SigningKeyPem))
        {
            try
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(_config.SigningKeyPem);
                _rsaKey = new RsaSecurityKey(rsa) { KeyId = _kid };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading RSA key from PEM: {ex.Message}");
            }
        }
    }

    public string GenerateAccessToken(NetworcoIdUserDto user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), // User ID as subject
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName),
            new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName),
            new Claim("national_id", user.NationalId),
            new Claim("phone_number", user.PhoneNumber ?? ""),
            // Removed: role claim - authorization handled by resource server
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        SigningCredentials creds;
        if (_rsaKey != null)
        {
            creds = new SigningCredentials(_rsaKey, SecurityAlgorithms.RsaSha256);
        }
        else
        {
            var signingKey = _config.Secret 
                ?? throw new InvalidOperationException("JWT signing key not configured. Set NetworcoId:Secret, Auth:Jwt:SigningKey, or JWT_SECRET.");
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

    public JsonWebKeySet GetPublicKeys()
    {
        if (_rsaKey == null)
        {
            return new JsonWebKeySet();
        }

        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_rsaKey);
        jwk.Kid = _kid;
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.RsaSha256;

        return new JsonWebKeySet { Keys = { jwk } };
    }

    public string GenerateRefreshToken()
    {
        var randomBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        
        TokenValidationParameters validationParameters;

        if (_rsaKey != null)
        {
            validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _rsaKey,
                ValidateIssuer = true,
                ValidIssuer = _config.Issuer,
                ValidateAudience = true,
                ValidAudience = _config.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
        }
        else
        {
            var signingKey = _config.Secret 
                ?? throw new InvalidOperationException("JWT signing key not configured.");
            var key = Encoding.UTF8.GetBytes(signingKey);
            validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _config.Issuer,
                ValidateAudience = true,
                ValidAudience = _config.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
        }

        try
        {
            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }
}
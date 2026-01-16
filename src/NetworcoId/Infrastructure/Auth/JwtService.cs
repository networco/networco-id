using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NetworcoId.Models.Auth;
using NetworcoId.Core.Models;

namespace NetworcoId.Infrastructure.Auth;

/// <summary>
/// JWT token service.
/// </summary>
public interface IJwtService
{
    string GenerateAccessToken(NetworcoIdUserDto user);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
}

/// <summary>
/// JWT token service implementation.
/// </summary>
public class JwtService : IJwtService
{
    private readonly NetworcoIdConfig _config;

    public JwtService(NetworcoIdConfig config)
    {
        _config = config;
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

        var signingKey = _config.Secret 
            ?? throw new InvalidOperationException("JWT signing key not configured. Set NetworcoId:Secret, Auth:Jwt:SigningKey, or JWT_SECRET.");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config.Issuer,
            audience: _config.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_config.AccessTokenExpirationMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
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
        var signingKey = _config.Secret 
            ?? throw new InvalidOperationException("JWT signing key not configured.");
        var key = Encoding.UTF8.GetBytes(signingKey);

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _config.Issuer,
                ValidateAudience = true,
                ValidAudience = _config.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out _);

            return principal;
        }
        catch
        {
            return null;
        }
    }
}
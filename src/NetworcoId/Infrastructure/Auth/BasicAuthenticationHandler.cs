using System.Net.Http.Headers;
using System.Text;

namespace NetworcoId.Infrastructure.Auth;

/// <summary>
/// Helper to extract Basic Authentication credentials.
/// </summary>
public static class BasicAuthenticationHandler
{
    public static bool TryGetBasicCredentials(HttpContext context, out string? clientId, out string? clientSecret)
    {
        clientId = null;
        clientSecret = null;

        try
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var parameter = authHeader.Substring("Basic ".Length).Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parameter));
            var parts = decoded.Split(':', 2);

            if (parts.Length == 2)
            {
                clientId = Uri.UnescapeDataString(parts[0]);
                clientSecret = Uri.UnescapeDataString(parts[1]);
                return true;
            }
        }
        catch
        {
            // Ignore parsing errors
        }

        return false;
    }
}

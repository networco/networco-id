using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Services;
using NetworcoId.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace NetworcoId.Pages;

public class VerifyModel(
    AuthDbContext dbContext,
    IAuthService authService,
    ILogger<VerifyModel> logger) : PageModel
{
    public bool IsVerified { get; set; }
    public string? ErrorMessage { get; set; }
    public string? AuthorizationUrl { get; set; }
    public string? Token { get; set; }
    public string ReturnUrl { get; set; } = string.Empty;

    public async Task<IActionResult> OnGetAsync(string? token, string? return_url)
    {
        if (string.IsNullOrEmpty(token))
        {
            ErrorMessage = "Mangler bekreftelsestoken";
            return Page();
        }

        Token = token;
        ReturnUrl = return_url ?? "http://localhost:3000";

        try
        {
            var user = await dbContext.Users.AsTracking()
                .FirstOrDefaultAsync(u => u.EmailVerificationToken == token);

            if (user == null)
            {
                ErrorMessage = "Ugyldig bekreftelsestoken";
                return Page();
            }

            if (user.EmailVerificationTokenExpiresAt < DateTimeOffset.UtcNow)
            {
                ErrorMessage = "Bekreftelsestoken har utløpt";
                return Page();
            }

            // Mark email as verified and clear token
            user.EmailVerified = true;
            user.EmailVerificationToken = null;
            user.EmailVerificationTokenExpiresAt = null;

            await dbContext.SaveChangesAsync();

            logger.LogInformation("User {Email} verified, creating OAuth session", user.Email);

            // Create OAuth authorization code for auto-login
            var finalRedirectUri = ReturnUrl;
            var state = Guid.NewGuid().ToString();

            // Try to extract client_id and redirect_uri from ReturnUrl if it's an OAuth callback
            string? clientId = null;
            try
            {
                // In production, ReturnUrl from email might be double-encoded or contain the full redirect URL
                // Check if ReturnUrl itself looks like a full URL with OAuth params
                var uriString = ReturnUrl;
                if (uriString.StartsWith("/"))
                {
                    uriString = "http://localhost" + uriString;
                }

                var uri = new Uri(uriString);
                var query = HttpUtility.ParseQueryString(uri.Query);
                
                clientId = query["client_id"];
                var oauthRedirectUri = query["redirect_uri"];
                var oauthState = query["state"];

                // If ReturnUrl was /Login?client_id=...&redirect_uri=..., then oauthRedirectUri is what we want
                if (!string.IsNullOrEmpty(oauthRedirectUri))
                {
                    finalRedirectUri = oauthRedirectUri;
                }
                
                // CRITICAL: Preserve the original state so returnPath survives
                if (!string.IsNullOrEmpty(oauthState))
                {
                    state = oauthState;
                }
                
                logger.LogInformation("Extracted OAuth params from ReturnUrl: ClientId={ClientId}, RedirectUri={RedirectUri}, State={State}", 
                    clientId, finalRedirectUri, state);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to extract OAuth params from ReturnUrl: {ReturnUrl}", ReturnUrl);
            }

            var authCode = authService.CreateAuthorizationCode(user.Email, finalRedirectUri, state, clientId);

            // Build callback URL
            AuthorizationUrl = $"{finalRedirectUri}{(finalRedirectUri.Contains("?") ? "&" : "?")}code={authCode}&state={state}";
            IsVerified = true;

            return Page();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during email verification");
            ErrorMessage = "Bekreftelse feilet";
            return Page();
        }
    }
}

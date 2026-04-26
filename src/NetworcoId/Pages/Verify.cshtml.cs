using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Services;
using NetworcoId.Services.Messaging;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace NetworcoId.Pages;

public class VerifyModel(
    AuthDbContext dbContext,
    IAuthService authService,
    IEmailService emailService,
    IOptions<NetworcoIdConfig> config,
    ILogger<VerifyModel> logger) : PageModel
{
    private readonly NetworcoIdConfig _config = config.Value;
    public bool IsVerified { get; set; }
    public string? ErrorMessage { get; set; }
    public string? AuthorizationUrl { get; set; }
    public string? Token { get; set; }
    public string ReturnUrl { get; set; } = string.Empty;
    /// <summary>
    /// True when the email was verified but the same-browser cookie didn't match
    /// (e.g. the link was opened on a different device). Auto-login is skipped
    /// and the user is told to log in with their password instead.
    /// </summary>
    public bool RequiresManualLogin { get; set; }
    /// <summary>URL the user can click to log in after manual-login fallback.</summary>
    public string LoginUrl { get; set; } = "/Login";
    /// <summary>True after a fresh verification email has been requested via the resend form.</summary>
    public bool VerificationEmailResent { get; set; }
    /// <summary>True when the failure is recoverable by sending a new link
    /// (expired or token-not-found, but NOT for missing token).</summary>
    public bool CanResendVerification { get; set; }

    public async Task<IActionResult> OnGetAsync(string? token, string? return_url)
    {
        if (string.IsNullOrEmpty(token))
        {
            ErrorMessage = "Mangler bekreftelsestoken";
            return Page();
        }

        Token = token;
        ReturnUrl = !string.IsNullOrWhiteSpace(return_url) ? return_url : _config.FrontendUrl;

        try
        {
            // Tolerate both the URL-safe Base64 form (current) and the legacy
            // raw-Base64 form (before the Register.cshtml.cs fix). The query
            // parser also turns `+` into a space; restore it before lookup.
            var normalizedToken = token.Replace(' ', '+');
            var legacyToken = normalizedToken.Replace('-', '+').Replace('_', '/');

            var user = await dbContext.Users.AsTracking()
                .FirstOrDefaultAsync(u =>
                    u.EmailVerificationToken == token ||
                    u.EmailVerificationToken == normalizedToken ||
                    u.EmailVerificationToken == legacyToken);

            if (user == null)
            {
                ErrorMessage = "Ugyldig bekreftelsestoken";
                CanResendVerification = true;
                return Page();
            }

            if (user.EmailVerificationTokenExpiresAt < DateTimeOffset.UtcNow)
            {
                ErrorMessage = "Bekreftelsestoken har utløpt";
                CanResendVerification = true;
                return Page();
            }

            // Same-browser binding check. If the cookie set at registration
            // doesn't match the user's stored session id, we skip the auto-login
            // step — the link was likely opened on a different device, which is
            // exactly the email-interception scenario we want to defend against.
            var cookieSessionId = Request.Cookies[RegisterModel.VerifyCookieName];
            var sameBrowser = !string.IsNullOrEmpty(user.EmailVerificationSessionId)
                && !string.IsNullOrEmpty(cookieSessionId)
                && string.Equals(user.EmailVerificationSessionId, cookieSessionId, StringComparison.Ordinal);

            // Mark email as verified and clear the verification token + session id
            // (single use either way — the user is verified and the link is spent).
            user.EmailVerified = true;
            user.EmailVerificationToken = null;
            user.EmailVerificationTokenExpiresAt = null;
            user.EmailVerificationSessionId = null;

            await dbContext.SaveChangesAsync();

            // Always clear the binding cookie too so it can't be replayed.
            Response.Cookies.Delete(RegisterModel.VerifyCookieName);

            // Build a sensible login URL we can show on the manual-login screen.
            // Preserves the original OAuth params if the user came via /Login so
            // they can resume the same flow after authenticating.
            LoginUrl = ReturnUrl.StartsWith("/Login", StringComparison.OrdinalIgnoreCase)
                ? ReturnUrl
                : "/Login";

            if (!sameBrowser)
            {
                logger.LogInformation("User {Email} verified on a different browser/device — skipping auto-login", user.Email);
                IsVerified = true;
                RequiresManualLogin = true;
                return Page();
            }

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

            var authCode = await authService.CreateAuthorizationCodeAsync(user.Email, finalRedirectUri, state, clientId);

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

    /// <summary>
    /// POST handler for the "Send ny lenke" form on the expired/invalid-link
    /// fallback. Issues a fresh verification token + cookie and queues the
    /// email. Always reports success to avoid leaking which addresses are
    /// registered.
    /// </summary>
    public async Task<IActionResult> OnPostResendAsync()
    {
        var resendEmail = Request.Form["resendEmail"].ToString().Trim();
        var formReturnUrl = Request.Form["return_url"].ToString();
        ReturnUrl = !string.IsNullOrWhiteSpace(formReturnUrl) ? formReturnUrl : _config.FrontendUrl;
        VerificationEmailResent = true;

        if (string.IsNullOrWhiteSpace(resendEmail))
        {
            return Page();
        }

        var user = await dbContext.Users.AsTracking()
            .FirstOrDefaultAsync(u => u.Email != null && u.Email.ToLower() == resendEmail.ToLower());

        if (user == null || user.EmailVerified)
        {
            logger.LogInformation("Resend-verification requested for {Email} (no-op: not found or already verified)", resendEmail);
            return Page();
        }

        await EmailVerificationHelper.SendAsync(
            HttpContext, dbContext, emailService, user, _config.BaseUrl, ReturnUrl);

        logger.LogInformation("Resent verification email for {Email}", resendEmail);
        return Page();
    }
}

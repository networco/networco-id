using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using NetworcoId.Models.Auth;
using NetworcoId.Services;

namespace NetworcoId.Endpoints;

/// <summary>
/// External (federated) login endpoints. NetworcoId acts as a relying party to
/// IDura, which brokers Norwegian BankID.
///
/// Flow: /auth/external/bankid challenges the "idura" OpenIdConnect scheme →
/// IDura/BankID → the OIDC middleware handles the callback at
/// <c>IduraCallbackPath</c> (default /auth/callback/external), signing the
/// external identity into the short-lived "ExternalLogin" cookie → it then
/// redirects to /auth/external/complete, which find-or-creates the local user,
/// establishes the normal session cookie, and resumes the original
/// /oauth/authorize request so the main site's OAuth flow continues unchanged.
/// </summary>
public static class ExternalAuthEndpoints
{
    private const string Provider = "idura";
    private const string ExternalScheme = "ExternalLogin";

    public static void MapExternalAuth(this WebApplication app)
    {
        // Step 1 — initiate the BankID challenge.
        app.MapGet("/auth/external/bankid", (HttpContext context, string? returnUrl, NetworcoIdConfig config) =>
        {
            if (!config.IduraEnabled)
            {
                return Results.NotFound();
            }

            // Carry the original /oauth/authorize request through the external round-trip.
            var safeReturn = IsValidReturnUrl(returnUrl) ? returnUrl! : string.Empty;
            var completeUrl = "/auth/external/complete"
                + (safeReturn.Length > 0 ? "?returnUrl=" + Uri.EscapeDataString(safeReturn) : string.Empty);

            var props = new AuthenticationProperties { RedirectUri = completeUrl };
            return Results.Challenge(props, new[] { Provider });
        })
        .WithName("ExternalBankIdChallenge")
        .RequireRateLimiting("auth-strict")
        .AllowAnonymous();

        // Step 2 — finish: build/link the local user and resume the OAuth flow.
        app.MapGet("/auth/external/complete", async (
            HttpContext context,
            string? returnUrl,
            IAuthService authService,
            IClientManagementService clientService,
            NetworcoIdConfig config,
            ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger("ExternalAuth");

            if (!config.IduraEnabled)
            {
                return Results.NotFound();
            }

            var result = await context.AuthenticateAsync(ExternalScheme);
            if (!result.Succeeded || result.Principal is null)
            {
                logger.LogWarning("External login completion failed: no external identity present");
                return Results.Redirect("/Login?error=external");
            }

            var principal = result.Principal;
            var subject = principal.FindFirst("sub")?.Value
                          ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(subject))
            {
                logger.LogWarning("External login completion failed: provider returned no subject");
                await context.SignOutAsync(ExternalScheme);
                return Results.Redirect("/Login?error=external");
            }

            // Log the claim names the provider returned (names only — no values) so we
            // can see which BankID reference claims are available (sub, national id, etc.).
            logger.LogInformation("External login claims: [{ClaimTypes}] (emailVerified={EmailVerified})",
                string.Join(", ", principal.Claims.Select(c => c.Type).Distinct()),
                principal.FindFirst("email_verified")?.Value ?? "<none>");

            var (firstName, lastName) = ResolveName(principal);
            var info = new ExternalUserInfo
            {
                Subject = subject,
                Email = principal.FindFirst("email")?.Value,
                EmailVerified = ParseBool(principal.FindFirst("email_verified")?.Value),
                FirstName = firstName,
                LastName = lastName,
                BirthDate = principal.FindFirst("birthdate")?.Value
            };

            var user = await authService.FindOrCreateExternalUserAsync(Provider, info);

            // Establish the normal session — identical claim shape to password login
            // (see Login.cshtml.cs) so /oauth/authorize treats this session the same.
            var authTime = DateTimeOffset.UtcNow;
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.Email),
                new Claim("sub", user.Id.ToString()),
                new Claim("auth_time", authTime.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("external_login_provider", Provider)
            };

            if (user.Roles != null)
            {
                foreach (var role in user.Roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity),
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(60)
                });

            // Drop the temporary external cookie.
            await context.SignOutAsync(ExternalScheme);

            logger.LogInformation("External login complete for user {UserId} via {Provider}", user.Id, Provider);

            // Resume the original OAuth request — /oauth/authorize sees the session
            // cookie and silently issues the code back to the relying party.
            var destination = IsValidReturnUrl(returnUrl)
                ? returnUrl!
                : await ResolveFallbackDestinationAsync(clientService, config, logger);

            return Results.Redirect(destination);
        })
        .WithName("ExternalBankIdComplete")
        .AllowAnonymous();
    }

    /// <summary>
    /// returnUrl must be a local path back into the OAuth authorize endpoint —
    /// prevents this endpoint being abused as an open redirector.
    /// </summary>
    private static bool IsValidReturnUrl(string? url) =>
        !string.IsNullOrEmpty(url) && url.StartsWith("/oauth/authorize", StringComparison.OrdinalIgnoreCase);

    private static bool ParseBool(string? value) =>
        value != null && (value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1");

    private static (string? FirstName, string? LastName) ResolveName(ClaimsPrincipal principal)
    {
        var given = principal.FindFirst("given_name")?.Value;
        var family = principal.FindFirst("family_name")?.Value;
        if (!string.IsNullOrWhiteSpace(given) || !string.IsNullOrWhiteSpace(family))
        {
            return (given, family);
        }

        // Fall back to splitting the full name if only `name` was provided.
        var name = principal.FindFirst("name")?.Value;
        if (!string.IsNullOrWhiteSpace(name))
        {
            var parts = name.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length == 2 ? (parts[0], parts[1]) : (parts[0], string.Empty);
        }

        return (null, null);
    }

    /// <summary>
    /// Where to send a user who arrived without a valid OAuth returnUrl — mirrors
    /// the Login page's fallback: the default client's origin, else FrontendUrl.
    /// </summary>
    private static async Task<string> ResolveFallbackDestinationAsync(
        IClientManagementService clientService, NetworcoIdConfig config, ILogger logger)
    {
        try
        {
            var defaultClient = await clientService.GetDefaultClientAsync();
            var firstRedirect = defaultClient?.RedirectUris.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(firstRedirect)
                && Uri.TryCreate(firstRedirect, UriKind.Absolute, out var redirectUri))
            {
                return $"{redirectUri.Scheme}://{redirectUri.Authority}";
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "External login: failed to resolve default client fallback");
        }

        return config.FrontendUrl;
    }
}

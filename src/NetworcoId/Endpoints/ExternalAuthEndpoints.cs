using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
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
    internal const string Provider = "idura";
    internal const string ExternalScheme = "ExternalLogin";
    // AuthenticationProperties.Items keys carried through the BankID round-trip in link mode.
    private const string LinkUserIdItem = "link_user_id";
    private const string LinkReturnItem = "link_return";

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

        // Step 1b — mint a one-time link ticket for the AUTHENTICATED user. Called
        // server-to-server by the relying party (the NETWORCO app proxies it) with the
        // user's access token, so we authorize the link by the token — not the (maybe
        // expired) NETWORCO ID session.
        app.MapPost("/auth/external/link/start", async (HttpContext context, IAuthService authService, NetworcoIdConfig config) =>
        {
            if (!config.IduraEnabled) return Results.NotFound();

            var sub = context.User.FindFirst("sub")?.Value;
            if (!Guid.TryParse(sub, out var userId)) return Results.Unauthorized();

            var ticket = await authService.CreateBankIdLinkTicketAsync(userId);
            return Results.Ok(new { ticket });
        })
        .WithName("ExternalBankIdLinkStart")
        .RequireRateLimiting("auth-strict")
        .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });

        // Step 1c — connect BankID to an EXISTING account (verify-to-link). The browser
        // arrives here with a one-time ticket; we resolve it to the target account and
        // start the BankID challenge in "link mode" (the account id rides through the
        // round-trip in the protected auth properties).
        app.MapGet("/auth/external/link", async (HttpContext context, string? ticket, string? returnPath, IAuthService authService, NetworcoIdConfig config) =>
        {
            if (!config.IduraEnabled) return Results.NotFound();

            var userId = await authService.ConsumeBankIdLinkTicketAsync(ticket ?? string.Empty);
            if (userId is null)
            {
                // Expired/invalid ticket — bounce back to the app with an error flag.
                var rp = IsSafeRelativePath(returnPath) ? returnPath! : "/settings";
                var sep0 = rp.Contains('?') ? "&" : "?";
                return Results.Redirect($"{config.FrontendUrl.TrimEnd('/')}{rp}{sep0}bankid=error");
            }

            var props = new AuthenticationProperties { RedirectUri = "/auth/external/complete" };
            props.Items[LinkUserIdItem] = userId.Value.ToString();
            if (IsSafeRelativePath(returnPath)) props.Items[LinkReturnItem] = returnPath!;
            return Results.Challenge(props, new[] { Provider });
        })
        .WithName("ExternalBankIdLink")
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

            // --- LINK MODE (verify-to-link / step-up) ---
            // The challenge was initiated by /auth/external/link, which stashed the id of
            // the already-authenticated account. Attach the BankID to THAT account and
            // return to the app — never create a new account or touch the email.
            var items = result.Properties?.Items;
            if (items != null && items.TryGetValue(LinkUserIdItem, out var linkUserIdStr)
                && Guid.TryParse(linkUserIdStr, out var linkUserId))
            {
                var linkResult = await authService.LinkExternalUserAsync(linkUserId, Provider, info);
                await context.SignOutAsync(ExternalScheme);
                logger.LogInformation("BankID link for user {UserId}: {Result}", linkUserId, linkResult);

                var returnPath = items.TryGetValue(LinkReturnItem, out var rp) && IsSafeRelativePath(rp)
                    ? rp!
                    : "/settings";
                var status = linkResult == ExternalLinkResult.UserNotFound ? "error" : "linked";
                var sep = returnPath.Contains('?') ? "&" : "?";
                return Results.Redirect($"{config.FrontendUrl.TrimEnd('/')}{returnPath}{sep}bankid={status}");
            }

            // --- LOGIN MODE ---
            // A BankID may be linked to several accounts (one person, multiple accounts).
            // When it resolves to 2+, let the user choose; otherwise fall through to the
            // normal find-or-create (which also handles first-login and email conflicts).
            var accounts = await authService.GetAccountsForExternalLoginAsync(Provider, subject);
            if (accounts.Count >= 2)
            {
                // Keep the external cookie — /SelectAccount re-reads the subject from it.
                var safeReturn = IsValidReturnUrl(returnUrl) ? returnUrl! : string.Empty;
                var pickerUrl = "/SelectAccount"
                    + (safeReturn.Length > 0 ? "?returnUrl=" + Uri.EscapeDataString(safeReturn) : string.Empty);
                return Results.Redirect(pickerUrl);
            }

            NetworcoIdUserDto user;
            try
            {
                user = await authService.FindOrCreateExternalUserAsync(Provider, info);
            }
            catch (ExternalEmailConflictException)
            {
                // The eID-supplied email already belongs to another account and we can't
                // prove ownership. Don't silently create a placeholder duplicate — send the
                // user to the login page with a clear explanation, preserving the OAuth
                // context so they can sign in to their existing account and continue.
                logger.LogWarning("External login blocked for subject {Subject}: email already in use", subject);
                await context.SignOutAsync(ExternalScheme);

                var oauthQuery = string.Empty;
                if (IsValidReturnUrl(returnUrl))
                {
                    var qIndex = returnUrl!.IndexOf('?');
                    if (qIndex >= 0) oauthQuery = returnUrl[(qIndex + 1)..] + "&";
                }
                return Results.Redirect($"/Login?{oauthQuery}email_conflict=true");
            }

            var destination = await EstablishSessionAndGetDestinationAsync(context, user, returnUrl, clientService, config, logger);
            return Results.Redirect(destination);
        })
        .WithName("ExternalBankIdComplete")
        .AllowAnonymous();
    }

    /// <summary>
    /// Establishes the normal session for <paramref name="user"/> (identical claim shape to
    /// password login, so /oauth/authorize treats it the same), drops the temporary external
    /// cookie, and returns where to resume the original OAuth request. Shared by the BankID-login
    /// completion and the multi-account picker (which returns an IActionResult, not an IResult).
    /// </summary>
    internal static async Task<string> EstablishSessionAndGetDestinationAsync(
        HttpContext context,
        NetworcoIdUserDto user,
        string? returnUrl,
        IClientManagementService clientService,
        NetworcoIdConfig config,
        ILogger logger)
    {
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

        await context.SignOutAsync(ExternalScheme);
        logger.LogInformation("External login session established for user {UserId}", user.Id);

        return IsValidReturnUrl(returnUrl)
            ? returnUrl!
            : await ResolveFallbackDestinationAsync(clientService, config, logger);
    }

    /// <summary>A safe app-local return path: absolute-local ("/...") and not protocol-relative ("//").</summary>
    private static bool IsSafeRelativePath(string? path) =>
        !string.IsNullOrEmpty(path) && path.StartsWith('/') && !path.StartsWith("//");

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

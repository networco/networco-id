using System.Web;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using NetworcoId.Services.Messaging;
using NetworcoId.Services.Security;

namespace NetworcoId.Pages;

[IgnoreAntiforgeryToken]
[EnableRateLimiting("auth-login-strict")]
public class LoginModel(IAuthService authService, NetworcoIdConfig config, AuthDbContext dbContext, IEmailService emailService, ILogger<LoginModel> logger, ILockoutService lockoutService, IClientManagementService clientService) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? client_id { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? redirect_uri { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? state { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? scope { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? code_challenge { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? code_challenge_method { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? nonce { get; set; }

    public string? ClientId => client_id;
    public string? RedirectUri => redirect_uri;
    public string? State => state;
    public string? Scope => scope;
    public string? CodeChallenge => code_challenge;
    public string? CodeChallengeMethod => code_challenge_method;
    public string? Nonce => nonce;

    /// <summary>Whether external BankID login (via IDura) is configured/enabled.</summary>
    public bool IduraEnabled => config.IduraEnabled;

    /// <summary>
    /// Link target for the BankID button: initiates the external challenge and
    /// carries the original /oauth/authorize request as a returnUrl so the OAuth
    /// flow resumes after BankID completes. Falls back to a bare challenge when
    /// there's no OAuth context (direct visit).
    /// </summary>
    public string BankIdChallengeUrl =>
        BankIdChallenge.BuildUrl(ClientId, RedirectUri, Scope, State, CodeChallenge, CodeChallengeMethod, Nonce);

    [BindProperty(SupportsGet = true, Name = "registration")]
    public string? Registration { get; set; }

    public List<NetworcoIdUserDto> TestUsers => config.TestUsers;
    
    [BindProperty(SupportsGet = true)]
    public string? Error { get; set; }

    [BindProperty(SupportsGet = true, Name = "error_description")]
    public string? ErrorDescription { get; set; }

    /// <summary>
    /// Set after a BankID login was refused because the eID-supplied email already
    /// belongs to another account. Shows a friendly, actionable notice while keeping the
    /// login form visible (unlike <see cref="Error"/>, which renders a fatal client error).
    /// </summary>
    [BindProperty(SupportsGet = true, Name = "email_conflict")]
    public bool EmailConflict { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public string? ErrorMessage { get; set; }
    public bool IsRegistration => Registration == "true";
    public bool IsClientError { get; set; }
    /// <summary>True when the entered credentials were valid but the email
    /// hasn't been verified yet — surfaces the "send a new link" CTA.</summary>
    public bool RequiresEmailVerification { get; set; }
    /// <summary>True when a fresh verification email was just sent so the page
    /// can confirm "ny lenke sendt" to the user.</summary>
    public bool VerificationEmailResent { get; set; }
    /// <summary>Email being verified — pre-filled for the resend form.</summary>
    public string? UnverifiedEmail { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        // Fallback for missing properties
        client_id ??= Request.Query["client_id"];
        redirect_uri ??= Request.Query["redirect_uri"];
        state ??= Request.Query["state"];
        scope ??= Request.Query["scope"];
        code_challenge ??= Request.Query["code_challenge"];
        code_challenge_method ??= Request.Query["code_challenge_method"];
        nonce ??= Request.Query["nonce"];

        // Log parameters for debugging
        logger.LogInformation("Login OnGet: ClientId={ClientId}, RedirectUri={RedirectUri}", ClientId, RedirectUri);

        if (!string.IsNullOrEmpty(Error))
        {
            ErrorMessage = ErrorDescription ?? "En uventet feil oppstod";
            IsClientError = true;
            return Page();
        }

        // BankID login refused because the eID email is already in use by another account.
        // Show a clear, actionable notice but keep the login form visible (IsClientError
        // stays false) so the user can sign in to their existing account and continue.
        if (EmailConflict)
        {
            ErrorMessage = "E-postadressen som er knyttet til BankID-en din er allerede i bruk av en annen konto. "
                + "Er dette din konto? Logg inn under. Hvis ikke, ta kontakt med support.";
        }

        if (IsRegistration)
        {
            var returnUrl = Request.Path + Request.QueryString.ToString().Replace("registration=true", "");
            return RedirectToPage("/Register", new { return_url = returnUrl });
        }

        // Direct visit (e.g. bookmark) with no OAuth context — bounce somewhere
        // sensible so the user isn't stranded on a login form they can't submit.
        // Order: a client flagged as Default in admin → FrontendUrl as last resort.
        if (string.IsNullOrEmpty(ClientId) && string.IsNullOrEmpty(RedirectUri))
        {
            return Redirect(await ResolveFallbackDestinationAsync());
        }

        if (string.IsNullOrEmpty(ClientId) || string.IsNullOrEmpty(RedirectUri))
        {
            return Page();
        }

        // Validate client
        var client = await dbContext.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == ClientId);
        if (client == null)
        {
            return BadRequest($"Ugyldig Client ID: {ClientId}");
        }

        if (!client.IsActive)
        {
            return BadRequest("Denne applikasjonen er deaktivert");
        }

        if (!client.RedirectUris.Contains(RedirectUri))
        {
            return BadRequest($"Ugyldig Redirect URI for denne applikasjonen. Expected one of: {string.Join(", ", client.RedirectUris)}. Got: {RedirectUri}");
        }

        // Validate scopes
        if (!string.IsNullOrEmpty(Scope))
        {
            var requestedScopes = Scope.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            var invalidScopes = requestedScopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
            if (invalidScopes.Any())
            {
                ErrorMessage = $"Ugyldige scopes: {string.Join(", ", invalidScopes)}";
                IsClientError = true;
                return Page();
            }
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        try
        {
            // Fallback for missing properties in POST
            client_id ??= Request.Query["client_id"];
            if (string.IsNullOrEmpty(client_id) && Request.HasFormContentType) client_id = Request.Form["client_id"];
            
            redirect_uri ??= Request.Query["redirect_uri"];
            if (string.IsNullOrEmpty(redirect_uri) && Request.HasFormContentType) redirect_uri = Request.Form["redirect_uri"];

            state ??= Request.Query["state"];
            if (string.IsNullOrEmpty(state) && Request.HasFormContentType) state = Request.Form["state"];

            scope ??= Request.Query["scope"];
            if (string.IsNullOrEmpty(scope) && Request.HasFormContentType) scope = Request.Form["scope"];

            code_challenge ??= Request.Query["code_challenge"];
            if (string.IsNullOrEmpty(code_challenge) && Request.HasFormContentType) code_challenge = Request.Form["code_challenge"];

            code_challenge_method ??= Request.Query["code_challenge_method"];
            if (string.IsNullOrEmpty(code_challenge_method) && Request.HasFormContentType) code_challenge_method = Request.Form["code_challenge_method"];

            nonce ??= Request.Query["nonce"];
            if (string.IsNullOrEmpty(nonce) && Request.HasFormContentType) nonce = Request.Form["nonce"];

            logger.LogInformation("LOGIN POST: Scope raw value = '{Scope}'", scope);

            if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(Password))
            {
                ErrorMessage = "E-post og passord er påkrevd";
                return Page();
            }

            if (string.IsNullOrEmpty(RedirectUri))
            {
                // Defensive fallback — the GET handler should have bounced the
                // user already, so this only fires on direct POSTs without the
                // proper OAuth carry-through. Resolve through the same default-
                // client → FrontendUrl chain instead of returning a 400.
                logger.LogWarning("Login Post: redirect_uri is missing. Resolving fallback destination. ClientId={ClientId}", ClientId);
                return Redirect(await ResolveFallbackDestinationAsync());
            }

            logger.LogInformation("Login Post: Email={Email}, ClientId={ClientId}, RedirectUri={RedirectUri}", Email, ClientId, RedirectUri);

            // Check IP Lockout
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            if (await lockoutService.IsLockedAsync(ip))
            {
                logger.LogWarning("Login attempt from locked IP: {Ip}", ip);
                ErrorMessage = "Din IP-adresse er midlertidig sperret pga. for mange feilede forsøk.";
                return Page();
            }

            // Authenticate user
            var user = await authService.AuthenticateUserAsync(Email, Password);
            if (user == null)
            {
                logger.LogWarning("Login Post: Authentication failed for {Email}", Email);
                
                // Record IP failure
                await lockoutService.RecordFailureAsync(ip);

                // Check for account lockout or increment failed attempts
                var credential = await dbContext.UserCredentials
                    .Include(c => c.User)
                    .FirstOrDefaultAsync(c => c.User.Email == Email);

                if (credential != null)
                {
                    credential.FailedLoginAttempts++;
                    credential.LastFailedLoginAt = DateTimeOffset.UtcNow;
                    
                    if (credential.FailedLoginAttempts >= config.MaxFailedLoginAttempts)
                    {
                        credential.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(config.LockoutDurationMinutes);
                        logger.LogWarning("Account {Email} locked until {LockedUntil}", Email, credential.LockedUntil);
                        ErrorMessage = $"Kontoen er låst i {config.LockoutDurationMinutes} minutter pga. for mange feilede forsøk.";
                    }
                    else
                    {
                        ErrorMessage = "Ugyldig e-post eller passord";
                    }

                    dbContext.UserCredentials.Update(credential);
                    await dbContext.SaveChangesAsync();
                }
                else
                {
                    ErrorMessage = "Ugyldig e-post eller passord";
                }
                
                return Page();
            }

            // Check if locked
            var userCreds = await dbContext.UserCredentials.AsNoTracking().FirstOrDefaultAsync(c => c.Id == user.Id);
            if (userCreds?.LockedUntil > DateTimeOffset.UtcNow)
            {
                ErrorMessage = $"Kontoen er låst frem til {userCreds.LockedUntil.Value.LocalDateTime:HH:mm}.";
                return Page();
            }

            // Reset failed attempts on success
            if (userCreds?.FailedLoginAttempts > 0)
            {
                var credToUpdate = await dbContext.UserCredentials.FirstOrDefaultAsync(c => c.Id == user.Id);
                if (credToUpdate != null)
                {
                    credToUpdate.FailedLoginAttempts = 0;
                    credToUpdate.LockedUntil = null;
                    dbContext.UserCredentials.Update(credToUpdate);
                    await dbContext.SaveChangesAsync();
                }
            }

            // Reset IP failure on success
            var ipSuccess = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await lockoutService.ResetAsync(ipSuccess);

            // Block login until the user has verified their email. We surface a
            // resend CTA so anyone whose verification link expired (or got lost)
            // can request a fresh one without re-registering.
            if (!user.EmailVerified)
            {
                logger.LogInformation("Login blocked for {Email}: email not verified", Email);
                ErrorMessage = "E-postadressen din er ikke bekreftet ennå. Sjekk innboksen din eller send en ny lenke.";
                RequiresEmailVerification = true;
                UnverifiedEmail = Email;
                return Page();
            }

            if (user.MustChangePassword)
            {
                logger.LogInformation("User {Email} must change password. Redirecting to /ChangePassword", Email);
                return RedirectToPage("/ChangePassword", new
                {
                    email = Email,
                    client_id = ClientId,
                    redirect_uri = RedirectUri,
                    state = State,
                    scope = Scope,
                    code_challenge = CodeChallenge,
                    code_challenge_method = CodeChallengeMethod
                });
            }

            // Store current time as auth_time in cookie claim
            var authTime = DateTimeOffset.UtcNow;
            
            // Create Cookie Session
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.Email),
                new Claim("sub", user.Id.ToString()),
                new Claim("auth_time", authTime.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64) // Store auth_time
            };

            // Add roles to cookie session so [AdminAuth] and other policies work
            if (user.Roles != null)
            {
                foreach (var role in user.Roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(60)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            // Create authorization code
            var requestedScopes = Scope?.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).ToList();
            logger.LogInformation("LOGIN POST: Creating Auth Code with Scopes = {Scopes}", requestedScopes == null ? "NULL" : string.Join(",", requestedScopes));

            // Pass the authTime to the auth code so it can be put in the ID token
            var code = await authService.CreateAuthorizationCodeAsync(user.Email, RedirectUri, State, ClientId, CodeChallenge, CodeChallengeMethod, Nonce, requestedScopes, authTime);

            // Build redirect URL
            var redirectUrl = new UriBuilder(RedirectUri);
            var query = HttpUtility.ParseQueryString(redirectUrl.Query);
            query["code"] = code;
            if (!string.IsNullOrEmpty(State))
            {
                query["state"] = State;
            }
            redirectUrl.Query = query.ToString();

            return Redirect(redirectUrl.ToString());
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error in Login OnPostAsync");
            return StatusCode(500, ex.ToString());
        }
    }

    /// <summary>
    /// POST handler for the "Send ny lenke" button on the unverified-email
    /// fallback. Issues a fresh verification token + cookie and queues the
    /// email. Always reports success even if the email doesn't match a real
    /// user — avoids leaking which addresses are registered.
    /// </summary>
    public async Task<IActionResult> OnPostResendVerificationAsync()
    {
        // Re-bind OAuth carry-through params so the page renders correctly on return.
        client_id ??= Request.Form["client_id"];
        redirect_uri ??= Request.Form["redirect_uri"];
        state ??= Request.Form["state"];
        scope ??= Request.Form["scope"];
        code_challenge ??= Request.Form["code_challenge"];
        code_challenge_method ??= Request.Form["code_challenge_method"];
        nonce ??= Request.Form["nonce"];

        var resendEmail = Request.Form["resendEmail"].ToString().Trim();
        UnverifiedEmail = resendEmail;
        VerificationEmailResent = true;

        if (string.IsNullOrWhiteSpace(resendEmail))
        {
            return Page();
        }

        var user = await dbContext.Users.AsTracking()
            .FirstOrDefaultAsync(u => u.Email != null && u.Email.ToLower() == resendEmail.ToLower());

        // Silently no-op for unknown emails or already-verified accounts.
        if (user == null || user.EmailVerified)
        {
            logger.LogInformation("Resend-verification requested for {Email} (no-op: not found or already verified)", resendEmail);
            return Page();
        }

        // Carry the original OAuth params through the verify return_url so the
        // user lands back on the same auth flow after they finally verify.
        var returnUrl = !string.IsNullOrEmpty(redirect_uri)
            ? $"/Login?{Request.Form.Where(kv => new[] { "client_id", "redirect_uri", "state", "scope" }.Contains(kv.Key)).Aggregate(string.Empty, (acc, kv) => acc + (acc.Length > 0 ? "&" : "") + $"{kv.Key}={Uri.EscapeDataString(kv.Value!)}")}"
            : config.FrontendUrl;

        await EmailVerificationHelper.SendAsync(
            HttpContext, dbContext, emailService, user, config.BaseUrl, returnUrl);

        logger.LogInformation("Resent verification email for {Email}", resendEmail);
        return Page();
    }

    /// <summary>
    /// Resolves where to bounce a user who hit /Login without OAuth params.
    /// Prefers the client flagged Default in admin (its first registered
    /// RedirectUri's origin → likely the app's home page), falling back to
    /// the configured FrontendUrl. Self-resolution: never returns an empty
    /// or absolute /Login URL that would loop back into this handler.
    /// </summary>
    private async Task<string> ResolveFallbackDestinationAsync()
    {
        var defaultClient = await clientService.GetDefaultClientAsync();
        var firstRedirect = defaultClient?.RedirectUris.FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(firstRedirect)
            && Uri.TryCreate(firstRedirect, UriKind.Absolute, out var redirectUri))
        {
            // Use the redirect URI's origin (scheme + host[:port]) — the
            // raw RedirectUri is typically a callback path that errors out
            // when hit without an auth code.
            var origin = $"{redirectUri.Scheme}://{redirectUri.Authority}";
            logger.LogInformation("Login fallback: bouncing to default client {ClientId} origin {Origin}", defaultClient!.ClientId, origin);
            return origin;
        }

        logger.LogInformation("Login fallback: no default client configured — bouncing to FrontendUrl");
        return config.FrontendUrl;
    }
}

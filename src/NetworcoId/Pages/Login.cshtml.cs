using System.Web;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Services;

namespace NetworcoId.Pages;

[IgnoreAntiforgeryToken]
public class LoginModel(IAuthService authService, NetworcoIdConfig config, AuthDbContext dbContext, ILogger<LoginModel> logger) : PageModel
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

    [BindProperty(SupportsGet = true, Name = "registration")]
    public string? Registration { get; set; }

    public List<NetworcoIdUserDto> TestUsers => config.TestUsers;
    
    [BindProperty(SupportsGet = true)]
    public string? Error { get; set; }

    [BindProperty(SupportsGet = true, Name = "error_description")]
    public string? ErrorDescription { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public string? ErrorMessage { get; set; }
    public bool IsRegistration => Registration == "true";
    public bool IsClientError { get; set; }

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

        if (IsRegistration)
        {
            var returnUrl = Request.Path + Request.QueryString.ToString().Replace("registration=true", "");
            return RedirectToPage("/Register", new { return_url = returnUrl });
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
                logger.LogWarning("Login Post: redirect_uri is missing. ClientId={ClientId}", ClientId);
                return BadRequest("redirect_uri er påkrevd");
            }

            logger.LogInformation("Login Post: Email={Email}, ClientId={ClientId}, RedirectUri={RedirectUri}", Email, ClientId, RedirectUri);

            // Authenticate user
            var user = await authService.AuthenticateUserAsync(Email, Password);
            if (user == null)
            {
                logger.LogWarning("Login Post: Authentication failed for {Email}", Email);
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
            var code = authService.CreateAuthorizationCode(user.Email, RedirectUri, State, ClientId, CodeChallenge, CodeChallengeMethod, Nonce, requestedScopes, authTime);

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
}

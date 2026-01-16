using System.Web;
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

    public string? ClientId => client_id;
    public string? RedirectUri => redirect_uri;
    public string? State => state;
    public string? Scope => scope;

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
                    scope = Scope
                });
            }

            // Create authorization code
            var code = authService.CreateAuthorizationCode(user.Email, RedirectUri, State, ClientId);

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

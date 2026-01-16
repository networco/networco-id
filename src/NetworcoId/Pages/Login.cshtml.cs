using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Services;

namespace NetworcoId.Pages;

public class LoginModel(IAuthService authService, NetworcoIdConfig config, AuthDbContext dbContext) : PageModel
{
    [BindProperty(SupportsGet = true, Name = "client_id")]
    public string? ClientId { get; set; }

    [BindProperty(SupportsGet = true, Name = "redirect_uri")]
    public string? RedirectUri { get; set; }

    [BindProperty(SupportsGet = true, Name = "state")]
    public string? State { get; set; }

    [BindProperty(SupportsGet = true, Name = "scope")]
    public string? Scope { get; set; }

    [BindProperty(SupportsGet = true, Name = "registration")]
    public string? Registration { get; set; }

    public List<NetworcoIdUserDto> TestUsers => config.TestUsers;
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
        // Log parameters for debugging
        Console.WriteLine($"Login OnGet: ClientId={ClientId}, RedirectUri={RedirectUri}");

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
            ErrorMessage = "client_id og redirect_uri er påkrevd";
            IsClientError = true;
            return Page();
        }

        // Validate client
        var client = await dbContext.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == ClientId);
        if (client == null)
        {
            ErrorMessage = $"Ugyldig Client ID: {ClientId}";
            IsClientError = true;
            return Page();
        }

        if (!client.IsActive)
        {
            ErrorMessage = "Denne applikasjonen er deaktivert";
            IsClientError = true;
            return Page();
        }

        if (!client.RedirectUris.Contains(RedirectUri))
        {
            ErrorMessage = "Ugyldig Redirect URI for denne applikasjonen";
            IsClientError = true;
            return Page();
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
        if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(Password))
        {
            ErrorMessage = "E-post og passord er påkrevd";
            return Page();
        }

        if (string.IsNullOrEmpty(RedirectUri))
        {
            return BadRequest("redirect_uri er påkrevd");
        }

        // Authenticate user
        var user = await authService.AuthenticateUserAsync(Email, Password);
        if (user == null)
        {
            ErrorMessage = "Ugyldig e-post eller passord";
            return Page();
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
}

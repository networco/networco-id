using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Core.Security;
using NetworcoId.Models.Auth;
using NetworcoId.Services;

namespace NetworcoId.Pages;

[IgnoreAntiforgeryToken]
public class ChangePasswordModel(IAuthService authService, NetworcoIdConfig config, IPasswordValidator passwordValidator) : PageModel
{
    public int MinPasswordLength => config.MinPasswordLength;
    public string PasswordRequirementsHint => PasswordPolicyText.BuildHint(config);

    [BindProperty(SupportsGet = true)]
    public string? Email { get; set; }

    [BindProperty(SupportsGet = true, Name = "client_id")]
    public string? ClientId { get; set; }

    [BindProperty(SupportsGet = true, Name = "redirect_uri")]
    public string? RedirectUri { get; set; }

    [BindProperty(SupportsGet = true, Name = "state")]
    public string? State { get; set; }

    [BindProperty(SupportsGet = true, Name = "scope")]
    public string? Scope { get; set; }

    [BindProperty]
    public string CurrentPassword { get; set; } = string.Empty;

    [BindProperty]
    public string NewPassword { get; set; } = string.Empty;

    [BindProperty]
    public string ConfirmPassword { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        // Manual parameter extraction as fallback for WebApplicationFactory
        Email ??= Request.Form["Email"].FirstOrDefault() ?? Request.Query["Email"].FirstOrDefault();
        ClientId ??= Request.Form["client_id"].FirstOrDefault() ?? Request.Query["client_id"].FirstOrDefault();
        RedirectUri ??= Request.Form["redirect_uri"].FirstOrDefault() ?? Request.Query["redirect_uri"].FirstOrDefault();
        State ??= Request.Form["state"].FirstOrDefault() ?? Request.Query["state"].FirstOrDefault();
        Scope ??= Request.Form["scope"].FirstOrDefault() ?? Request.Query["scope"].FirstOrDefault();

        if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(CurrentPassword) || string.IsNullOrEmpty(NewPassword))
        {
            ErrorMessage = "Alle felt må fylles ut";
            return Page();
        }

        if (NewPassword != ConfirmPassword)
        {
            ErrorMessage = "Nye passord samsvarer ikke";
            return Page();
        }

        var validationResult = passwordValidator.Validate(
            NewPassword,
            config.MinPasswordLength,
            config.RequireDigit,
            config.RequireUppercase,
            config.RequireLowercase,
            config.RequireNonAlphanumeric);

        if (!validationResult.IsValid)
        {
            ErrorMessage = validationResult.ErrorMessage;
            return Page();
        }

        if (CurrentPassword == NewPassword)
        {
            ErrorMessage = "Nytt passord kan ikke være det samme som nåværende passord";
            return Page();
        }

        var result = await authService.ChangePasswordAsync(Email, CurrentPassword, NewPassword);
        if (!result)
        {
            ErrorMessage = "Kunne ikke endre passord. Vennligst sjekk at nåværende passord er riktig.";
            return Page();
        }

        // Redirect back to login to complete the flow
        return RedirectToPage("/Login", new
        {
            client_id = ClientId,
            redirect_uri = RedirectUri,
            state = State,
            scope = Scope,
            email = Email
        });
    }
}

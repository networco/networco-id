using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Services;

namespace NetworcoId.Pages;

public class ChangePasswordModel(IAuthService authService) : PageModel
{
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

        if (NewPassword.Length < 12)
        {
            ErrorMessage = "Passordet må være minst 12 tegn langt";
            return Page();
        }

        if (!NewPassword.Any(char.IsUpper) || !NewPassword.Any(char.IsLower) || !NewPassword.Any(char.IsDigit))
        {
            ErrorMessage = "Passordet må inneholde store og små bokstaver, samt tall";
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

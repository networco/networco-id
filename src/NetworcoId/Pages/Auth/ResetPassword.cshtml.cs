using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Services;

using NetworcoId.Models.Auth;

namespace NetworcoId.Pages.Auth;

public class ResetPasswordModel(IAuthService authService, NetworcoIdConfig config) : PageModel
{
    public int MinPasswordLength => config.MinPasswordLength;

    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    [BindProperty]
    public string NewPassword { get; set; } = string.Empty;

    [BindProperty]
    public string ConfirmPassword { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }
    public string? SuccessMessage { get; set; }

    public IActionResult OnGet()
    {
        if (string.IsNullOrEmpty(Token))
        {
            return RedirectToPage("/Login");
        }
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrEmpty(Token))
        {
            return RedirectToPage("/Login");
        }

        if (string.IsNullOrEmpty(NewPassword) || string.IsNullOrEmpty(ConfirmPassword))
        {
            ErrorMessage = "Alle felt må fylles ut";
            return Page();
        }

        if (NewPassword != ConfirmPassword)
        {
            ErrorMessage = "Passordene samsvarer ikke";
            return Page();
        }

        try
        {
            var result = await authService.ResetPasswordWithTokenAsync(Token, NewPassword);
            if (!result)
            {
                ErrorMessage = "Lenken er ugyldig eller utløpt. Vennligst be om en ny lenke.";
                return Page();
            }

            SuccessMessage = "Ditt passord har blitt tilbakestilt. Du kan nå logge inn med det nye passordet ditt.";
            return Page();
        }
        catch (ArgumentException ex)
        {
            ErrorMessage = ex.Message;
            return Page();
        }
        catch (Exception)
        {
            ErrorMessage = "En uventet feil oppstod. Vennligst prøv igjen senere.";
            return Page();
        }
    }
}

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Services;
using NetworcoId.Models.Auth;

namespace NetworcoId.Pages.Auth;

public class ForgotPasswordModel(IAuthService authService) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? client_id { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? redirect_uri { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? state { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? scope { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    public string? ErrorMessage { get; set; }
    public string? SuccessMessage { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrWhiteSpace(Email))
        {
            ErrorMessage = "E-post er påkrevd";
            return Page();
        }

        await authService.InitiatePasswordResetAsync(Email);
        
        SuccessMessage = "Hvis e-postadressen er registrert hos oss, har vi sendt en lenke for å tilbakestille passordet.";
        return Page();
    }
}

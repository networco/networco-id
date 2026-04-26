using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Services;
using NetworcoId.Models.Auth;

namespace NetworcoId.Pages.Auth;

public class ForgotPasswordModel(IAuthService authService) : PageModel
{
    // BindProperty(SupportsGet) doesn't auto-bind on POST when the property is
    // also in the form body, so each handler also reads from Form/Query as a
    // fallback (see OnPostAsync). These are populated for the GET render and
    // round-tripped through hidden form inputs.
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
        // Hidden form inputs carry the OAuth params from the originating
        // /Login. Re-bind them so we can pass them along to the reset email.
        client_id ??= Request.Form["client_id"];
        redirect_uri ??= Request.Form["redirect_uri"];
        state ??= Request.Form["state"];
        scope ??= Request.Form["scope"];

        if (string.IsNullOrWhiteSpace(Email))
        {
            ErrorMessage = "E-post er påkrevd";
            return Page();
        }

        // Build the same /Login return URL we'd want the user to come back
        // to after the reset succeeds — preserves their original OAuth flow.
        var returnUrl = BuildLoginReturnUrl();

        await authService.InitiatePasswordResetAsync(Email, returnUrl);

        SuccessMessage = "Hvis e-postadressen er registrert hos oss, har vi sendt en lenke for å tilbakestille passordet.";
        return Page();
    }

    private string? BuildLoginReturnUrl()
    {
        if (string.IsNullOrWhiteSpace(client_id) || string.IsNullOrWhiteSpace(redirect_uri))
        {
            return null;
        }
        return Url.Page("/Login", new
        {
            client_id,
            redirect_uri,
            state,
            scope,
        });
    }
}

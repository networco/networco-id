using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using NetworcoId.Endpoints;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using System.Security.Claims;

namespace NetworcoId.Pages;

/// <summary>
/// Account picker shown after a successful BankID login when the eID identity is linked to
/// more than one local account (one person, several accounts). The just-completed BankID is
/// re-read from the external cookie, so the user can only ever choose among their OWN linked
/// accounts. Picking one establishes a single-account session and resumes the OAuth flow.
/// </summary>
public class SelectAccountModel(
    IAuthService authService,
    IClientManagementService clientService,
    IOptions<NetworcoIdConfig> config,
    ILogger<SelectAccountModel> logger) : PageModel
{
    private readonly NetworcoIdConfig _config = config.Value;

    public record AccountChoice(Guid Id, string MaskedEmail, string Name, string Roles);

    public List<AccountChoice> Accounts { get; private set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var subject = await ResolveSubjectAsync();
        if (subject is null) return Redirect("/Login?error=external");

        var accounts = await authService.GetAccountsForExternalLoginAsync(ExternalAuthEndpoints.Provider, subject);

        // Defensive: only the genuine 2+ case needs a picker. With 0/1 just hand back to
        // the normal completion path rather than rendering an empty/pointless chooser.
        if (accounts.Count == 0) return Redirect("/Login?error=external");
        if (accounts.Count == 1)
        {
            var dest1 = await ExternalAuthEndpoints.EstablishSessionAndGetDestinationAsync(
                HttpContext, accounts[0], ReturnUrl, clientService, _config, logger);
            return Redirect(dest1);
        }

        Accounts = accounts.Select(ToChoice).ToList();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(Guid selectedUserId)
    {
        var subject = await ResolveSubjectAsync();
        if (subject is null) return Redirect("/Login?error=external");

        var accounts = await authService.GetAccountsForExternalLoginAsync(ExternalAuthEndpoints.Provider, subject);
        var chosen = accounts.FirstOrDefault(a => a.Id == selectedUserId);
        if (chosen is null)
        {
            // The choice wasn't among this BankID's accounts — re-render the picker.
            logger.LogWarning("SelectAccount: rejected choice {UserId} not linked to subject", selectedUserId);
            Accounts = accounts.Select(ToChoice).ToList();
            return Page();
        }

        var destination = await ExternalAuthEndpoints.EstablishSessionAndGetDestinationAsync(
            HttpContext, chosen, ReturnUrl, clientService, _config, logger);
        return Redirect(destination);
    }

    private async Task<string?> ResolveSubjectAsync()
    {
        var result = await HttpContext.AuthenticateAsync(ExternalAuthEndpoints.ExternalScheme);
        if (!result.Succeeded || result.Principal is null) return null;
        return result.Principal.FindFirst("sub")?.Value
               ?? result.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    }

    private static AccountChoice ToChoice(NetworcoIdUserDto u) => new(
        u.Id,
        MaskEmail(u.Email),
        $"{u.FirstName} {u.LastName}".Trim(),
        u.Roles != null && u.Roles.Count > 0 ? string.Join(", ", u.Roles) : "");

    /// <summary>Masks an email for display: <c>ola@example.com</c> → <c>o***@example.com</c>.</summary>
    private static string MaskEmail(string email)
    {
        var at = email.IndexOf('@');
        if (at <= 0) return email;
        var local = email[..at];
        var shown = local.Length <= 1 ? local : local[0] + "***";
        return shown + email[at..];
    }
}

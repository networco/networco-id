using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Services;

namespace NetworcoId.Pages;

/// <summary>
/// Lets a logged-in user set (or replace) a password. The primary audience is
/// BankID-only users who have no credential yet and want to opt into password
/// login. Requires an active session cookie; no current password is asked for.
/// </summary>
[IgnoreAntiforgeryToken]
public class SetPasswordModel(IAuthService authService, NetworcoIdConfig config, AuthDbContext dbContext) : PageModel
{
    public int MinPasswordLength => config.MinPasswordLength;
    public string PasswordRequirementsHint => PasswordPolicyText.BuildHint(config);

    [BindProperty]
    public string NewPassword { get; set; } = string.Empty;

    [BindProperty]
    public string ConfirmPassword { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }
    public bool Success { get; set; }
    public bool AlreadyHasPassword { get; set; }
    /// <summary>True when the account's email is unverified (e.g. a BankID placeholder)
    /// — password login won't work until a real, verified email is in place.</summary>
    public bool NeedsEmailVerification { get; set; }
    public string? Email { get; set; }

    private Guid? CurrentUserId()
    {
        var sub = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(sub, out var id) ? id : null;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var userId = CurrentUserId();
        if (userId is null)
        {
            return RedirectToPage("/Login");
        }

        await LoadStateAsync(userId.Value);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var userId = CurrentUserId();
        if (userId is null)
        {
            return RedirectToPage("/Login");
        }

        await LoadStateAsync(userId.Value);

        if (string.IsNullOrEmpty(NewPassword))
        {
            ErrorMessage = "Du må fylle ut et passord";
            return Page();
        }

        if (NewPassword != ConfirmPassword)
        {
            ErrorMessage = "Passordene samsvarer ikke";
            return Page();
        }

        try
        {
            var ok = await authService.SetPasswordAsync(userId.Value, NewPassword);
            if (!ok)
            {
                ErrorMessage = "Kunne ikke sette passord. Prøv igjen.";
                return Page();
            }
        }
        catch (ArgumentException ex)
        {
            ErrorMessage = ex.Message;
            return Page();
        }

        Success = true;
        AlreadyHasPassword = true;
        return Page();
    }

    private async Task LoadStateAsync(Guid userId)
    {
        var user = await dbContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId);
        Email = user?.Email;
        NeedsEmailVerification = user != null && !user.EmailVerified;
        AlreadyHasPassword = await authService.HasPasswordAsync(userId);
    }
}

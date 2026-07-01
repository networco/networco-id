using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services.Audit;
using NetworcoId.Infrastructure.Auth;

namespace NetworcoId.Pages.Admin.Users;

[AdminAuth]
public class EditModel : PageModel
{
    private readonly AuthDbContext _context;
    private readonly IAuditService _auditService;

    public EditModel(AuthDbContext context, IAuditService auditService)
    {
        _context = context;
        _auditService = auditService;
    }

    [BindProperty]
    public UserEntity UserData { get; set; } = null!;

    public int ActiveAdminCount { get; set; }

    public List<string> InternalRoles { get; set; } = new() { "admin", "user" };

    [BindProperty]
    public List<string> SelectedRoles { get; set; } = new();

    [BindProperty]
    public string? Roles { get; set; }

    /// <summary>External (federated) logins linked to this user, e.g. BankID via
    /// IDura. The Subject is the provider reference used for identity resolution.</summary>
    public List<UserExternalLoginEntity> ExternalLogins { get; set; } = new();

    public async Task<IActionResult> OnGetAsync(Guid id)
    {
        var user = await _context.Users
            .Include(u => u.Credential)
            .FirstOrDefaultAsync(u => u.Id == id);

        if (user == null)
        {
            return NotFound();
        }

        UserData = user;

        ExternalLogins = await _context.UserExternalLogins
            .AsNoTracking()
            .Where(e => e.UserId == id)
            .OrderBy(e => e.Provider)
            .ToListAsync();
        SelectedRoles = user.Roles.Intersect(InternalRoles).ToList();
        
        // Custom roles go into the Tag UI
        Roles = string.Join(",", user.Roles.Except(InternalRoles));
        
        ActiveAdminCount = await _context.Users.CountAsync(u => u.IsActive && u.Roles.Contains("admin"));

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(Guid id)
    {
        var user = await _context.Users
            .Include(u => u.Credential)
            .FirstOrDefaultAsync(u => u.Id == id);

        if (user == null)
        {
            return NotFound();
        }

        // Load external logins up-front so any `return Page()` validation path below
        // still renders the External Logins section and the BankID caveat note.
        ExternalLogins = await _context.UserExternalLogins
            .AsNoTracking()
            .Where(e => e.UserId == id)
            .OrderBy(e => e.Provider)
            .ToListAsync();

        // Security: Prevent deactivating the last admin
        if (!UserData.IsActive && user.IsActive && user.Roles?.Contains("admin") == true)
        {
            var adminCount = await _context.Users.CountAsync(u => u.IsActive && u.Roles.Contains("admin"));
            if (adminCount <= 1)
            {
                ModelState.AddModelError("UserData.IsActive", "Cannot deactivate the last remaining active administrator.");
                UserData = user;
                ActiveAdminCount = adminCount;
                return Page();
            }
        }

        // Merge roles from checkboxes and tags
        var customRoles = (Roles ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(r => r.ToLowerInvariant())
            .ToList();
        
        var allRoles = SelectedRoles.Concat(customRoles).Distinct().ToList();

        // Security: Prevent removing the last admin role
        if (user.Roles != null && user.Roles.Contains("admin") && !allRoles.Contains("admin"))
        {
            var adminCount = await _context.Users.CountAsync(u => u.IsActive && u.Roles.Contains("admin"));
            if (adminCount <= 1 && user.IsActive)
            {
                ModelState.AddModelError("Roles", "Cannot remove the last remaining active administrator role.");
                UserData = user;
                ActiveAdminCount = adminCount;
                return Page();
            }
        }

        // Update basic info.
        // NOTE: NationalId is deliberately NOT assigned from the form — it's an identity
        // reference shown read-only in the UI. Ignoring it here means a tampered/forged
        // post cannot change it (server-side whitelist).
        user.FirstName = UserData.FirstName;
        user.LastName = UserData.LastName;
        user.Email = UserData.Email;
        user.PhoneNumber = UserData.PhoneNumber;
        user.IsActive = UserData.IsActive;
        user.Roles = allRoles;

        // Update Address
        user.AddressStreetAddress = UserData.AddressStreetAddress;
        user.AddressPostalCode = UserData.AddressPostalCode;
        user.AddressLocality = UserData.AddressLocality;
        user.AddressRegion = UserData.AddressRegion;
        user.AddressCountry = UserData.AddressCountry;
        user.AddressFormatted = $"{UserData.AddressStreetAddress}, {UserData.AddressPostalCode} {UserData.AddressLocality}, {UserData.AddressRegion}, {UserData.AddressCountry}"
            .Replace(", ,", ",")
            .Trim(',', ' ');

        _context.Users.Update(user);
        await _context.SaveChangesAsync();

        await _auditService.LogAsync("UserUpdated", $"User updated via admin: {user.Email}", id);
        TempData["StatusMessage"] = $"User {user.Email} has been updated successfully.";

        return RedirectToPage("./Index");
    }

    public async Task<IActionResult> OnPostUnlockAsync(Guid id)
    {
        var credential = await _context.UserCredentials.FirstOrDefaultAsync(c => c.Id == id);
        if (credential != null)
        {
            credential.FailedLoginAttempts = 0;
            credential.LockedUntil = null;
            
            _context.UserCredentials.Update(credential);
            await _context.SaveChangesAsync();
            
            var user = await _context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
            await _auditService.LogAsync("UserUnlocked", $"User account unlocked manually via Edit: {user?.Email}", id);
            
            TempData["StatusMessage"] = $"User {user?.Email} has been unlocked.";
        }

        return RedirectToPage(new { id });
    }
}

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

        // Update basic info
        user.FirstName = UserData.FirstName;
        user.LastName = UserData.LastName;
        user.Email = UserData.Email;
        user.NationalId = UserData.NationalId;
        user.PhoneNumber = UserData.PhoneNumber;
        user.IsActive = UserData.IsActive;

        // Roles management (simple toggle for admin in this case)
        var isAdminRequested = Request.Form["IsAdmin"] == "true";
        if (isAdminRequested != user.Roles?.Contains("admin"))
        {
            user.Roles ??= new List<string>();
            if (isAdminRequested)
            {
                user.Roles.Add("admin");
            }
            else
            {
                // Security: Prevent removing the last admin role
                var adminCount = await _context.Users.CountAsync(u => u.IsActive && u.Roles.Contains("admin"));
                if (adminCount <= 1 && user.IsActive)
                {
                    ModelState.AddModelError("UserData.Roles", "Cannot remove the last remaining active administrator role.");
                    UserData = user;
                    ActiveAdminCount = adminCount;
                    return Page();
                }
                user.Roles.Remove("admin");
            }
        }

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

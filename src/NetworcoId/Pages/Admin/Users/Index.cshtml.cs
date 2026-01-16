using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services.Audit;

using NetworcoId.Infrastructure.Auth;

namespace NetworcoId.Pages.Admin.Users;

[AdminAuth]
public class IndexModel : PageModel
{
    private readonly AuthDbContext _context;
    private readonly IAuditService _auditService;

    public IndexModel(AuthDbContext context, IAuditService auditService)
    {
        _context = context;
        _auditService = auditService;
    }

    public List<UserEntity> Users { get; set; } = new();

    public async Task OnGetAsync()
    {
        Users = await _context.Users
            .Include(u => u.Credential)
            .OrderByDescending(u => u.CreatedAt)
            .ToListAsync();
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
            await _auditService.LogAsync("UserUnlocked", $"User account unlocked manually: {user?.Email}", id);
            
            TempData["StatusMessage"] = $"User {user?.Email} has been unlocked.";
        }

        return RedirectToPage();
    }
    
    public async Task<IActionResult> OnPostToggleStatusAsync(Guid id)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
        if (user != null)
        {
            user.IsActive = !user.IsActive;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            
            await _auditService.LogAsync("UserStatusToggled", $"User status toggled to {(user.IsActive ? "Active" : "Inactive")}: {user.Email}", id);
            
            TempData["StatusMessage"] = $"User {user.Email} is now {(user.IsActive ? "Active" : "Inactive")}.";
        }

        return RedirectToPage();
    }
}
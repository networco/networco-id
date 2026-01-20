using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services.Audit;

using NetworcoId.Infrastructure.Auth;

using NetworcoId.Models.Common;

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

    public PagedResult<UserEntity> Users { get; set; } = null!;
    public int ActiveAdminCount { get; set; }

    [BindProperty(SupportsGet = true)]
    public int PageNumber { get; set; } = 1;

    [BindProperty(SupportsGet = true)]
    public string? SearchTerm { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? SortBy { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool SortDescending { get; set; } = true;

    public async Task OnGetAsync()
    {
        ActiveAdminCount = await _context.Users.CountAsync(u => u.IsActive && u.Roles.Contains("admin"));
        var query = _context.Users
            .Include(u => u.Credential)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(SearchTerm))
        {
            query = query.Where(u => u.Email.Contains(SearchTerm) || u.FirstName.Contains(SearchTerm) || u.LastName.Contains(SearchTerm));
        }

        query = SortBy?.ToLower() switch
        {
            "email" => SortDescending ? query.OrderByDescending(u => u.Email) : query.OrderBy(u => u.Email),
            "firstname" => SortDescending ? query.OrderByDescending(u => u.FirstName) : query.OrderBy(u => u.FirstName),
            "lastname" => SortDescending ? query.OrderByDescending(u => u.LastName) : query.OrderBy(u => u.LastName),
            "isactive" => SortDescending ? query.OrderByDescending(u => u.IsActive) : query.OrderBy(u => u.IsActive),
            _ => SortDescending ? query.OrderByDescending(u => u.CreatedAt) : query.OrderBy(u => u.CreatedAt)
        };

        var totalItems = await query.CountAsync();
        var items = await query
            .Skip((PageNumber - 1) * 10)
            .Take(10)
            .ToListAsync();

        Users = new PagedResult<UserEntity>
        {
            Items = items,
            TotalItems = totalItems,
            PageNumber = PageNumber,
            PageSize = 10
        };
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
            // Security: Prevent deactivating the last admin
            if (user.IsActive && user.Roles?.Contains("admin") == true)
            {
                var adminCount = await _context.Users.CountAsync(u => u.IsActive && u.Roles.Contains("admin"));
                if (adminCount <= 1)
                {
                    TempData["StatusMessage"] = "Error: Cannot deactivate the last remaining active administrator.";
                    return RedirectToPage();
                }
            }

            user.IsActive = !user.IsActive;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            
            await _auditService.LogAsync("UserStatusToggled", $"User status toggled to {(user.IsActive ? "Active" : "Inactive")}: {user.Email}", id);
            
            TempData["StatusMessage"] = $"User {user.Email} is now {(user.IsActive ? "Active" : "Inactive")}.";
        }

        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostDeleteAsync(Guid id)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
        if (user != null)
        {
            // Security: Prevent deleting the last admin
            if (user.Roles?.Contains("admin") == true)
            {
                var adminCount = await _context.Users.CountAsync(u => u.IsActive && u.Roles.Contains("admin"));
                if (adminCount <= 1)
                {
                    TempData["StatusMessage"] = "Error: Cannot delete the last remaining active administrator.";
                    return RedirectToPage();
                }
            }

            if (user.Email == "admin@networco.local")
            {
                TempData["StatusMessage"] = "Error: Cannot delete the system administrator.";
                return RedirectToPage();
            }

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("UserDeleted", $"User deleted: {user.Email}", id);
            TempData["StatusMessage"] = $"User {user.Email} has been deleted.";
        }

        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostToggleAdminAsync(Guid id)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
        if (user != null)
        {
            user.Roles ??= new List<string>();
            if (user.Roles.Contains("admin"))
            {
                // Security: Prevent removing the last admin role
                var adminCount = await _context.Users.CountAsync(u => u.IsActive && u.Roles.Contains("admin"));
                if (adminCount <= 1)
                {
                    TempData["StatusMessage"] = "Error: Cannot remove the last remaining active administrator.";
                    return RedirectToPage();
                }

                user.Roles.Remove("admin");
            }
            else
            {
                user.Roles.Add("admin");
            }
            
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            
            await _auditService.LogAsync("UserRoleChanged", $"User role toggled: {user.Email}", id);
            
            TempData["StatusMessage"] = $"Admin role toggled for {user.Email}.";
        }

        return RedirectToPage();
    }
}
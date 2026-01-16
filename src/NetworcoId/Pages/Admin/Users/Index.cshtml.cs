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
            user.IsActive = !user.IsActive;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            
            await _auditService.LogAsync("UserStatusToggled", $"User status toggled to {(user.IsActive ? "Active" : "Inactive")}: {user.Email}", id);
            
            TempData["StatusMessage"] = $"User {user.Email} is now {(user.IsActive ? "Active" : "Inactive")}.";
        }

        return RedirectToPage();
    }
}
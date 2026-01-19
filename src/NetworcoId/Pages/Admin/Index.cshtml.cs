using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Auth;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;

namespace NetworcoId.Pages.Admin;

[AdminAuth]
public class IndexModel(AuthDbContext context) : PageModel
{
    public int TotalUsers { get; set; }
    public int ActiveUsers { get; set; }
    public int TotalClients { get; set; }
    public List<AuditLogEntity> RecentLogs { get; set; } = [];
    public List<UserEntity> NewestUsers { get; set; } = [];

    public async Task OnGetAsync()
    {
        TotalUsers = await context.Users.CountAsync();
        ActiveUsers = await context.Users.CountAsync(u => u.IsActive);
        TotalClients = await context.OAuthClients.CountAsync();

        RecentLogs = await context.AuditLogs
            .Include(l => l.User)
            .OrderByDescending(l => l.Timestamp)
            .Take(5)
            .ToListAsync();

        NewestUsers = await context.Users
            .OrderByDescending(u => u.CreatedAt)
            .Take(5)
            .ToListAsync();
    }
}

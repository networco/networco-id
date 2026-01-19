using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;

using NetworcoId.Infrastructure.Auth;

using NetworcoId.Models.Common;

namespace NetworcoId.Pages.Admin.AuditLogs;

[AdminAuth]
public class IndexModel : PageModel
{
    private readonly AuthDbContext _context;

    public IndexModel(AuthDbContext context)
    {
        _context = context;
    }

    public PagedResult<AuditLogEntity> Logs { get; set; } = null!;

    [BindProperty(SupportsGet = true)]
    public string? EventType { get; set; }

    [BindProperty(SupportsGet = true)]
    public int PageNumber { get; set; } = 1;

    [BindProperty(SupportsGet = true)]
    public string? SearchTerm { get; set; }

    public List<string> EventTypes { get; set; } = new();

    public async Task OnGetAsync()
    {
        var query = _context.AuditLogs
            .Include(l => l.User)
            .OrderByDescending(l => l.Timestamp)
            .AsQueryable();

        if (!string.IsNullOrEmpty(EventType))
        {
            query = query.Where(l => l.EventType == EventType);
        }

        if (!string.IsNullOrWhiteSpace(SearchTerm))
        {
            query = query.Where(l => l.Description.Contains(SearchTerm) || (l.User != null && l.User.Email.Contains(SearchTerm)));
        }

        var totalItems = await query.CountAsync();
        var items = await query
            .Skip((PageNumber - 1) * 20)
            .Take(20)
            .ToListAsync();

        Logs = new PagedResult<AuditLogEntity>
        {
            Items = items,
            TotalItems = totalItems,
            PageNumber = PageNumber,
            PageSize = 20
        };

        EventTypes = await _context.AuditLogs
            .Select(l => l.EventType)
            .Distinct()
            .OrderBy(t => t)
            .ToListAsync();
    }
}
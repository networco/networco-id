using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Auth;
 using NetworcoId.Infrastructure.Database;
 using NetworcoId.Models.Auth;
 using NetworcoId.Models.Entities;
using NetworcoId.Services;

using NetworcoId.Models.Common;

namespace NetworcoId.Pages.Admin.Clients;

[AdminAuth]
 public class IndexModel(IClientManagementService clientService, Microsoft.Extensions.Options.IOptions<NetworcoIdConfig> config) : PageModel
 {
     public PagedResult<OAuthClientEntity> Clients { get; set; } = null!;
     public string? SystemClientId { get; set; } = config.Value.SystemManagementClientId;

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
        Clients = await clientService.GetClientsAsync(PageNumber, 10, SearchTerm, SortBy, SortDescending);
    }

    public async Task<IActionResult> OnPostToggleAsync(string id)
    {
        await clientService.ToggleClientStatusAsync(id);
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostDeleteAsync(string id)
    {
        await clientService.DeleteClientAsync(id);
        return RedirectToPage();
    }
}

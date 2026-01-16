using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Auth;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services;

namespace NetworcoId.Pages.Admin.Clients;

[AdminAuth]
public class IndexModel(IClientManagementService clientService) : PageModel
{
    public List<OAuthClientEntity> Clients { get; set; } = new();

    public async Task OnGetAsync()
    {
        Clients = await clientService.GetClientsAsync();
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

using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Auth;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Core.Security;
using NetworcoId.Services;

namespace NetworcoId.Pages.Admin.Clients;

[AdminAuth]
public class CreateModel(IClientManagementService clientManagementService) : PageModel
{
    [BindProperty]
    public string DisplayName { get; set; } = string.Empty;

    [BindProperty]
    public string RedirectUris { get; set; } = string.Empty;

    [BindProperty]
    public string Scopes { get; set; } = "openid,profile,email,offline_access";

    [BindProperty]
    public List<string> SelectedScopes { get; set; } = new() { "openid", "profile", "email", "offline_access" };

    public List<string> AvailableScopes { get; set; } = new()
    {
        "openid", "profile", "email", "phone", "address", "offline_access"
    };

    [BindProperty]
    public bool IsTrustedForExchange { get; set; }

    public string? CreatedClientId { get; set; }
    public string? CreatedSecret { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var redirectUriList = RedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        
        var scopeList = SelectedScopes.Any() 
            ? SelectedScopes 
            : Scopes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        var (client, secret) = await clientManagementService.CreateClientAsync(DisplayName, redirectUriList, scopeList, IsTrustedForExchange);

        CreatedClientId = client.ClientId;
        CreatedSecret = secret;

        return Page();
    }
}

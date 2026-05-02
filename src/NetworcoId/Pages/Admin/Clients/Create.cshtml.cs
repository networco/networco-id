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
    public string Audience { get; set; } = "networco-api";

    [BindProperty]
    public string RedirectUris { get; set; } = string.Empty;

    [BindProperty]
    public string? Scopes { get; set; } = string.Empty;

    [BindProperty]
    public List<string>? SelectedScopes { get; set; } = new();

    public List<string> AvailableScopes { get; set; } = new()
    {
        "openid", "profile", "email", "phone", "address", "offline_access"
    };

    [BindProperty]
    public bool IsTrustedForExchange { get; set; }

    [BindProperty]
    public bool IsDefault { get; set; }

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
        
        // Combine selected checkboxes with manual scopes
        var scopeList = SelectedScopes ?? new List<string>();
        if (!string.IsNullOrWhiteSpace(Scopes))
        {
            var manualScopes = Scopes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var s in manualScopes)
            {
                if (!scopeList.Contains(s)) scopeList.Add(s);
            }
        }

        var (client, secret) = await clientManagementService.CreateClientAsync(DisplayName, Audience, redirectUriList, scopeList, IsTrustedForExchange, IsDefault);

        CreatedClientId = client.ClientId;
        CreatedSecret = secret;

        return Page();
    }
}

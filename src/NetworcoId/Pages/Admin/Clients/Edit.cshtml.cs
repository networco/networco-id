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
public class EditModel(IClientManagementService clientService) : PageModel
{
    [BindProperty]
    public string ClientId { get; set; } = string.Empty;

    [BindProperty]
    public string DisplayName { get; set; } = string.Empty;

    [BindProperty]
    public string RedirectUris { get; set; } = string.Empty;

    [BindProperty]
    public string Scopes { get; set; } = string.Empty;

    public string? NewSecret { get; set; }
    public string? SecretType { get; set; } // "Primary" or "Secondary"

    public bool HasSecondarySecret { get; set; }

    public async Task<IActionResult> OnGetAsync(string id)
    {
        var client = await clientService.GetClientAsync(id);
        if (client == null)
        {
            return RedirectToPage("./Index");
        }

        ClientId = client.ClientId;
        DisplayName = client.DisplayName;
        RedirectUris = string.Join("\n", client.RedirectUris);
        Scopes = string.Join(", ", client.AllowedScopes);
        HasSecondarySecret = !string.IsNullOrEmpty(client.SecondaryClientSecretHash);

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var client = await clientService.GetClientAsync(ClientId);
        if (client == null)
        {
            return RedirectToPage("./Index");
        }

        var redirectUriList = RedirectUris.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();
        var scopeList = Scopes.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();

        await clientService.UpdateClientAsync(ClientId, DisplayName, redirectUriList, scopeList);

        return RedirectToPage(new { id = ClientId });
    }

    public async Task<IActionResult> OnPostRotatePrimaryAsync(string id)
    {
        var secret = await clientService.RotateClientSecretAsync(id, isPrimary: true);
        if (secret == null) return RedirectToPage("./Index");

        NewSecret = secret;
        SecretType = "Primary";
        
        await LoadClientProperties(id);

        return Page();
    }

    public async Task<IActionResult> OnPostRotateSecondaryAsync(string id)
    {
        var secret = await clientService.RotateClientSecretAsync(id, isPrimary: false);
        if (secret == null) return RedirectToPage("./Index");

        NewSecret = secret;
        SecretType = "Secondary";

        await LoadClientProperties(id);

        return Page();
    }

    public async Task<IActionResult> OnPostClearSecondaryAsync(string id)
    {
        await clientService.ClearSecondarySecretAsync(id);
        return RedirectToPage(new { id = id });
    }

    private async Task LoadClientProperties(string id)
    {
        var client = await clientService.GetClientAsync(id);
        if (client != null)
        {
            ClientId = client.ClientId;
            DisplayName = client.DisplayName;
            RedirectUris = string.Join("\n", client.RedirectUris);
            Scopes = string.Join(", ", client.AllowedScopes);
            HasSecondarySecret = !string.IsNullOrEmpty(client.SecondaryClientSecretHash);
        }
    }
}

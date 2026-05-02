using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Auth;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Core.Security;
using NetworcoId.Services;
using NetworcoId.Models.Auth;
using Microsoft.Extensions.Options;
using NetworcoId.Services.Audit;

namespace NetworcoId.Pages.Admin.Clients;

[AdminAuth]
public class EditModel(IClientManagementService clientService, IAuditService auditService) : PageModel
{
    [BindProperty]
    public string ClientId { get; set; } = string.Empty;

    [BindProperty]
    public string DisplayName { get; set; } = string.Empty;

    [BindProperty]
    public string Audience { get; set; } = string.Empty;

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

    public string? NewSecret { get; set; }
    public string? SecretType { get; set; } // "Primary" or "Secondary"

    public bool HasSecondarySecret { get; set; }
    public bool IsSystemClient { get; set; }

    [BindProperty]
    public bool IsActive { get; set; }

    public async Task<IActionResult> OnGetAsync(string id, [FromServices] IOptions<NetworcoIdConfig> config)
    {
        var client = await clientService.GetClientAsync(id);
        if (client == null)
        {
            return RedirectToPage("./Index");
        }

        IsSystemClient = client.ClientId == config.Value.SystemManagementClientId;
        ClientId = client.ClientId;
        DisplayName = client.DisplayName;
        Audience = client.Audience;
        RedirectUris = string.Join("\n", client.RedirectUris);
        Scopes = string.Join(", ", client.AllowedScopes);
        SelectedScopes = client.AllowedScopes;
        IsTrustedForExchange = client.IsTrustedForExchange;
        IsDefault = client.IsDefault;
        IsActive = client.IsActive;
        HasSecondarySecret = !string.IsNullOrEmpty(client.SecondaryClientSecretHash);

        return Page();
    }

    public async Task<IActionResult> OnPostAsync([FromServices] IOptions<NetworcoIdConfig> config)
    {
        var client = await clientService.GetClientAsync(ClientId);
        if (client == null)
        {
            return RedirectToPage("./Index");
        }

        if (client.ClientId == config.Value.SystemManagementClientId)
        {
            TempData["StatusMessage"] = "System client configuration is protected. Only secrets can be rotated.";
            return RedirectToPage(new { id = ClientId });
        }

        var redirectUriList = RedirectUris.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();
        
        var scopeList = SelectedScopes ?? new List<string>();
        if (!string.IsNullOrWhiteSpace(Scopes))
        {
            var manualScopes = Scopes.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim());
            foreach (var s in manualScopes)
            {
                if (!scopeList.Contains(s)) scopeList.Add(s);
            }
        }

        if (IsActive != client.IsActive)
        {
            await clientService.ToggleClientStatusAsync(ClientId);
        }

        await clientService.UpdateClientAsync(ClientId, DisplayName, Audience, redirectUriList, scopeList, IsTrustedForExchange, IsDefault);
        await auditService.LogAsync("ClientUpdated", $"OAuth client {ClientId} was updated.");

        return RedirectToPage(new { id = ClientId });
    }

    public async Task<IActionResult> OnPostRotatePrimaryAsync(string id, [FromServices] IOptions<NetworcoIdConfig> config)
    {
        var secret = await clientService.RotateClientSecretAsync(id, isPrimary: true);
        if (secret == null) return RedirectToPage("./Index");

        await auditService.LogAsync("ClientSecretRotated", $"Primary secret for client {id} was rotated.");

        NewSecret = secret;
        SecretType = "Primary";
        
        await LoadClientProperties(id, config.Value.SystemManagementClientId);

        return Page();
    }

    public async Task<IActionResult> OnPostRotateSecondaryAsync(string id, [FromServices] IOptions<NetworcoIdConfig> config)
    {
        var secret = await clientService.RotateClientSecretAsync(id, isPrimary: false);
        if (secret == null) return RedirectToPage("./Index");

        await auditService.LogAsync("ClientSecretRotated", $"Secondary secret for client {id} was {(HasSecondarySecret ? "rotated" : "generated")}.");

        NewSecret = secret;
        SecretType = "Secondary";

        await LoadClientProperties(id, config.Value.SystemManagementClientId);

        return Page();
    }

    public async Task<IActionResult> OnPostClearSecondaryAsync(string id)
    {
        await clientService.ClearSecondarySecretAsync(id);
        await auditService.LogAsync("ClientSecretCleared", $"Secondary secret for client {id} was cleared.");
        return RedirectToPage(new { id = id });
    }

    private async Task LoadClientProperties(string id, string? systemClientId)
    {
        var client = await clientService.GetClientAsync(id);
        if (client != null)
        {
            IsSystemClient = client.ClientId == systemClientId;
            ClientId = client.ClientId;
            DisplayName = client.DisplayName;
            Audience = client.Audience;
            RedirectUris = string.Join("\n", client.RedirectUris);
            Scopes = string.Join(", ", client.AllowedScopes);
            HasSecondarySecret = !string.IsNullOrEmpty(client.SecondaryClientSecretHash);
            IsActive = client.IsActive;
            IsTrustedForExchange = client.IsTrustedForExchange;
            IsDefault = client.IsDefault;
            SelectedScopes = client.AllowedScopes;
        }
    }
}

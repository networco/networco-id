using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using NetworcoId.Models.Auth;
using NetworcoId.Services.Audit;
using System.ComponentModel.DataAnnotations;

using NetworcoId.Infrastructure.Auth;

namespace NetworcoId.Pages.Admin.Settings;

[AdminAuth]
public class IndexModel : PageModel
{
    private readonly IAuditService _auditService;
    private readonly NetworcoIdConfig _config;

    public IndexModel(IAuditService auditService, NetworcoIdConfig config)
    {
        _auditService = auditService;
        _config = config;
    }

    [BindProperty]
    public SettingsInput Input { get; set; } = new();

    public class SettingsInput
    {
        [Display(Name = "Minimum Password Length")]
        [Range(8, 128)]
        public int MinPasswordLength { get; set; }

        [Display(Name = "Require Digit")]
        public bool RequireDigit { get; set; }

        [Display(Name = "Require Uppercase")]
        public bool RequireUppercase { get; set; }

        [Display(Name = "Require Lowercase")]
        public bool RequireLowercase { get; set; }

        [Display(Name = "Require Non-Alphanumeric")]
        public bool RequireNonAlphanumeric { get; set; }

        [Display(Name = "Max Failed Login Attempts")]
        [Range(1, 20)]
        public int MaxFailedLoginAttempts { get; set; }

        [Display(Name = "Lockout Duration (Minutes)")]
        [Range(1, 1440)]
        public int LockoutDurationMinutes { get; set; }
    }

    public void OnGet()
    {
        Input = new SettingsInput
        {
            MinPasswordLength = _config.MinPasswordLength,
            RequireDigit = _config.RequireDigit,
            RequireUppercase = _config.RequireUppercase,
            RequireLowercase = _config.RequireLowercase,
            RequireNonAlphanumeric = _config.RequireNonAlphanumeric,
            MaxFailedLoginAttempts = _config.MaxFailedLoginAttempts,
            LockoutDurationMinutes = _config.LockoutDurationMinutes
        };
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        // Note: In a real production system, these would be persisted to a database-backed configuration store
        // For this prototype, we update the singleton config object which persists for the application lifetime.
        
        _config.MinPasswordLength = Input.MinPasswordLength;
        _config.RequireDigit = Input.RequireDigit;
        _config.RequireUppercase = Input.RequireUppercase;
        _config.RequireLowercase = Input.RequireLowercase;
        _config.RequireNonAlphanumeric = Input.RequireNonAlphanumeric;
        _config.MaxFailedLoginAttempts = Input.MaxFailedLoginAttempts;
        _config.LockoutDurationMinutes = Input.LockoutDurationMinutes;

        await _auditService.LogAsync("SettingsUpdated", "System security settings were updated by administrator.");

        TempData["StatusMessage"] = "Settings updated successfully. Note: These changes are applied in-memory for the current session.";
        
        return RedirectToPage();
    }
}
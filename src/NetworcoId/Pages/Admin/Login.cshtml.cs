using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Hosting;
using NetworcoId.Models.Auth;
using NetworcoId.Services.Audit;
using NetworcoId.Services.Security;

namespace NetworcoId.Pages.Admin;

[EnableRateLimiting("admin-login-strict")]
public class LoginModel : PageModel
{
    private const string AdminKeyConfigName = "Admin:AccessKey";
    private const string AdminSessionCookie = "Networco_Admin_Session";

    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;
    private readonly IAuditService _auditService;
    private readonly ILockoutService _lockoutService;
    private readonly NetworcoIdConfig _idConfig;

    public LoginModel(IConfiguration config, IWebHostEnvironment env, IAuditService auditService, ILockoutService lockoutService, NetworcoIdConfig idConfig)
    {
        _config = config;
        _env = env;
        _auditService = auditService;
        _lockoutService = lockoutService;
        _idConfig = idConfig;
    }

    [BindProperty]
    public string Key { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Check Distributed IP Lockout
        if (await _lockoutService.IsLockedAsync(ip))
        {
            await _auditService.LogAsync("AdminLoginBlocked", $"Admin login attempt blocked due to IP lockout for: {ip}");
            ErrorMessage = "Din IP-adresse er midlertidig sperret pga. for mange feilede forsøk.";
            return Page();
        }

        var adminKey = _config[AdminKeyConfigName];

        if (string.IsNullOrEmpty(adminKey))
        {
            ErrorMessage = "Admin access is not configured.";
            return Page();
        }

        if (Key == adminKey)
        {
            Response.Cookies.Append(AdminSessionCookie, adminKey, new CookieOptions
            {
                HttpOnly = true,
                Secure = !_env.IsDevelopment(),
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(1)
            });

            // Reset IP failure on success
            await _lockoutService.ResetAsync(ip);

            await _auditService.LogAsync("AdminLogin", "Administrator logged in using access key.");

            return RedirectToPage("/Admin/Index");
        }

        // Record failure
        await _lockoutService.RecordFailureAsync(ip);

        await _auditService.LogAsync("AdminLoginFailed", "Failed admin login attempt with incorrect access key.");

        ErrorMessage = "Invalid access key.";
        return Page();
    }
}

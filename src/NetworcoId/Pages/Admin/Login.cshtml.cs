using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Hosting;
using NetworcoId.Services.Audit;

namespace NetworcoId.Pages.Admin;

public class LoginModel : PageModel
{
    private const string AdminKeyConfigName = "Admin:AccessKey";
    private const string AdminSessionCookie = "Networco_Admin_Session";

    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;
    private readonly IAuditService _auditService;

    public LoginModel(IConfiguration config, IWebHostEnvironment env, IAuditService auditService)
    {
        _config = config;
        _env = env;
        _auditService = auditService;
    }

    [BindProperty]
    public string Key { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
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

            await _auditService.LogAsync("AdminLogin", "Administrator logged in using access key.");

            return RedirectToPage("/Admin/Index");
        }

        await _auditService.LogAsync("AdminLoginFailed", "Failed admin login attempt with incorrect access key.");

        ErrorMessage = "Invalid access key.";
        return Page();
    }
}

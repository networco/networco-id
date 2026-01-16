using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Hosting;

namespace NetworcoId.Pages.Admin;

public class LoginModel : PageModel
{
    private const string AdminKeyConfigName = "Admin:AccessKey";
    private const string AdminSessionCookie = "Networco_Admin_Session";

    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;

    public LoginModel(IConfiguration config, IWebHostEnvironment env)
    {
        _config = config;
        _env = env;
    }

    [BindProperty]
    public string Key { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
    }

    public IActionResult OnPost()
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

            return RedirectToPage("/Admin/Clients/Index");
        }

        ErrorMessage = "Invalid access key.";
        return Page();
    }
}

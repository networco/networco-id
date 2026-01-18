using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Services;

namespace NetworcoId.Pages.Admin;

public class CallbackModel(
    IAuthService authService,
    IConfiguration configuration,
    IWebHostEnvironment env,
    ILogger<CallbackModel> logger) : PageModel
{
    private const string AdminSessionCookie = "Networco_Admin_Session";

    public async Task<IActionResult> OnGetAsync(string code)
    {
        if (string.IsNullOrEmpty(code))
        {
            return RedirectToPage("/Index");
        }

        // Validate the authorization code
        // For the admin portal, we expect the code to belong to the networco-admin client
        var result = await authService.ValidateAuthorizationCodeAsync(
            code, 
            "http://localhost:5200/admin/callback", 
            "networco-admin");

        if (result.User == null)
        {
            logger.LogWarning("Admin login failed: Invalid authorization code.");
            return RedirectToPage("/Admin/Login", new { error = "Session verification failed." });
        }

        // In this architecture, the admin panel uses the Admin:AccessKey for session authorization.
        // Once the user has successfully logged in via OAuth, we grant them the Admin session cookie.
        var adminKey = configuration["Admin:AccessKey"];
        if (string.IsNullOrEmpty(adminKey))
        {
            return StatusCode(403, "Admin access not configured.");
        }

        Response.Cookies.Append(AdminSessionCookie, adminKey, new CookieOptions
        {
            HttpOnly = true,
            Secure = !env.IsDevelopment(),
            SameSite = SameSiteMode.Strict,
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        });

        logger.LogInformation("Admin user {Email} logged in successfully via OAuth bootstrap.", result.User.Email);

        return RedirectToPage("/Admin/Clients/Index");
    }
}

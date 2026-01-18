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

        var config = configuration.GetSection("NetworcoId").Get<NetworcoId.Models.Auth.NetworcoIdConfig>();
        var redirectUri = $"{config?.BaseUrl.TrimEnd('/')}/admin/callback";

        // Validate the authorization code
        // For the admin portal, we expect the code to belong to the networco-admin client
        var result = await authService.ValidateAuthorizationCodeAsync(
            code, 
            redirectUri, 
            "networco-admin");

        if (result.User == null || !(result.User.Roles?.Contains("admin") ?? false))
        {
            logger.LogWarning("Admin login failed: Invalid authorization code or missing admin role. User: {User}, UserRoles: {UserRoles}, SessionScopes: {SessionScopes}", 
                result.User?.Email ?? "NULL", 
                string.Join(", ", result.User?.Roles ?? new List<string>()),
                string.Join(", ", result.Scopes ?? new List<string>()));
            return RedirectToPage("/Admin/Login", new { error = "Unauthorized access." });
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

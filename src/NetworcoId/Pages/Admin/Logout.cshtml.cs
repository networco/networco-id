using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Services.Audit;

namespace NetworcoId.Pages.Admin;

public class LogoutModel : PageModel
{
    private readonly IAuditService _auditService;

    public LogoutModel(IAuditService auditService)
    {
        _auditService = auditService;
    }

    public void OnGet()
    {
        // Redirect to Index or Login if they try to access via GET
        Response.Redirect("/Admin/Login");
    }

    public async Task<IActionResult> OnPostAsync()
    {
        // 1. Clear the admin session cookie
        Response.Cookies.Delete("Networco_Admin_Session");

        // 2. Sign out of the main authentication scheme to prevent auto-login
        // This is important because AdminAuthAttribute auto-grants access if user is logged in as admin
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        await _auditService.LogAsync("AdminLogout", "Administrator logged out of the admin panel.");

        return RedirectToPage("/Index");
    }
}

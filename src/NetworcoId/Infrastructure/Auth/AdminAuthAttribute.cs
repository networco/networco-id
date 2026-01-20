using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Hosting;

namespace NetworcoId.Infrastructure.Auth;

public class AdminAuthAttribute : Attribute, IAsyncPageFilter
{
    private const string AdminKeyConfigName = "Admin:AccessKey";
    private const string AdminSessionCookie = "Networco_Admin_Session";

    public async Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context)
    {
        await Task.CompletedTask;
    }

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
        var adminKey = config[AdminKeyConfigName];

        // If no admin key is configured, deny access by default for security
        if (string.IsNullOrEmpty(adminKey))
        {
            context.Result = new ContentResult { StatusCode = 403, Content = "Admin access not configured." };
            return;
        }

        // Check for cookie
        if (context.HttpContext.Request.Cookies.TryGetValue(AdminSessionCookie, out var cookieValue))
        {
            if (cookieValue == adminKey)
            {
                SetNoCacheHeaders(context.HttpContext.Response);
                await next();
                return;
            }
        }

        // Check if user is authenticated via OAuth and has the 'admin' role
        var user = context.HttpContext.User;
        if (user.Identity?.IsAuthenticated == true && user.IsInRole("admin"))
        {
            // Auto-grant the session cookie if they are a valid admin
            var env = context.HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>();
            context.HttpContext.Response.Cookies.Append(AdminSessionCookie, adminKey, new CookieOptions
            {
                HttpOnly = true,
                Secure = !env.IsDevelopment(),
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(1)
            });

            SetNoCacheHeaders(context.HttpContext.Response);
            await next();
            return;
        }

        var env2 = context.HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>();

        // Check for query param (to set cookie)
        if (context.HttpContext.Request.Query.TryGetValue("key", out var queryKey))
        {
            if (queryKey == adminKey)
            {
                // Set cookie and redirect to remove key from URL
                context.HttpContext.Response.Cookies.Append(AdminSessionCookie, adminKey, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = !env2.IsDevelopment(),
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(1)
                });

                var cleanUrl = context.HttpContext.Request.Path;
                context.Result = new RedirectResult(cleanUrl);
                return;
            }
        }

        // Not authenticated
        context.Result = new NotFoundResult();
    }

    private static void SetNoCacheHeaders(HttpResponse response)
    {
        response.Headers.Append("Cache-Control", "no-cache, no-store, must-revalidate");
        response.Headers.Append("Pragma", "no-cache");
        response.Headers.Append("Expires", "0");
    }
}

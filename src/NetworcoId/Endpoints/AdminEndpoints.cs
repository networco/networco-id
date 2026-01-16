using Microsoft.AspNetCore.Mvc;
using NetworcoId.Services;
using NetworcoId.Infrastructure.Database;
using Microsoft.EntityFrameworkCore;

namespace NetworcoId.Endpoints;

public static class AdminEndpoints
{
    private const string AdminKeyHeader = "X-Admin-Key";

    public static void MapAdmin(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/admin")
            .AddEndpointFilter(async (context, next) =>
            {
                var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
                var adminKey = config["Admin:AccessKey"];

                if (string.IsNullOrEmpty(adminKey))
                {
                    return Results.Content("Admin access not configured.", statusCode: 403);
                }

                // Check Header (for CLI/Postman)
                if (context.HttpContext.Request.Headers.TryGetValue(AdminKeyHeader, out var headerValue) &&
                    headerValue == adminKey)
                {
                    return await next(context);
                }

                // Check Cookie (for Admin UI fetch calls)
                if (context.HttpContext.Request.Cookies.TryGetValue("Networco_Admin_Session", out var cookieValue) &&
                    cookieValue == adminKey)
                {
                    return await next(context);
                }

                return Results.Json(new { error = "Unauthorized" }, statusCode: 401);
            });

        group.MapGet("/clients", async (IClientManagementService clientService) =>
        {
            var clients = await clientService.GetClientsAsync();
            return Results.Ok(clients);
        });

        group.MapPost("/clients", async ([FromBody] CreateClientRequest request, IClientManagementService clientService) =>
        {
            if (string.IsNullOrEmpty(request.DisplayName))
            {
                return Results.BadRequest(new { error = "DisplayName is required" });
            }

            var result = await clientService.CreateClientAsync(
                request.DisplayName, 
                request.RedirectUris ?? new List<string>(), 
                request.AllowedScopes ?? new List<string>(),
                request.IsTrustedForExchange);

            return Results.Ok(new 
            { 
                clientId = result.Client.ClientId, 
                clientSecret = result.Secret,
                message = "Client created successfully. Store the secret safely as it will not be shown again."
            });
        });

        group.MapPost("/clients/{id}/toggle", async (string id, IClientManagementService clientService) =>
        {
            var success = await clientService.ToggleClientStatusAsync(id);
            return success ? Results.Ok(new { message = "Client status toggled" }) : Results.NotFound();
        });

        group.MapDelete("/clients/{id}", async (string id, IClientManagementService clientService) =>
        {
            var success = await clientService.DeleteClientAsync(id);
            return success ? Results.Ok(new { message = "Client deleted" }) : Results.NotFound();
        });

        group.MapGet("/audit-logs", async (AuthDbContext db) =>
        {
            var logs = await db.AuditLogs
                .OrderByDescending(l => l.Timestamp)
                .Take(50)
                .ToListAsync();
            return Results.Ok(logs);
        });
    }

    public record CreateClientRequest(
        string DisplayName, 
        List<string>? RedirectUris, 
        List<string>? AllowedScopes,
        bool IsTrustedForExchange = false);
}

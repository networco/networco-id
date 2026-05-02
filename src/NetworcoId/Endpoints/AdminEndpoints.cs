using Microsoft.AspNetCore.Mvc;
using NetworcoId.Services;
using NetworcoId.Infrastructure.Database;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace NetworcoId.Endpoints;

public static class AdminEndpoints
{
    private const string AdminKeyHeader = "X-Admin-Key";

    public static void MapAdmin(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/admin")
            .RequireAuthorization(new AuthorizeAttribute 
            { 
                AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme,
                Roles = "admin" 
            });

        group.MapGet("/clients", async (IClientManagementService clientService, [FromQuery] int page = 1, [FromQuery] int pageSize = 10, [FromQuery] string? search = null) =>
        {
            var clients = await clientService.GetClientsAsync(page, pageSize, search);
            return Results.Ok(clients);
        });

        group.MapPost("/clients", async ([FromBody] CreateClientRequest request, IClientManagementService clientService) =>
        {
            if (string.IsNullOrEmpty(request.DisplayName))
            {
                return Results.BadRequest(new { error = "DisplayName is required" });
            }

            if (string.IsNullOrEmpty(request.Audience))
            {
                return Results.BadRequest(new { error = "Audience is required" });
            }

            var result = await clientService.CreateClientAsync(
                request.DisplayName,
                request.Audience,
                request.RedirectUris ?? new List<string>(),
                request.AllowedScopes ?? new List<string>(),
                request.IsTrustedForExchange,
                request.IsDefault);

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

        group.MapGet("/audit-logs", async (
            AuthDbContext db, 
            [FromQuery] int page = 1, 
            [FromQuery] int pageSize = 20,
            [FromQuery] string? eventType = null,
            [FromQuery] string? search = null) =>
        {
            var query = db.AuditLogs
                .Include(l => l.User)
                .OrderByDescending(l => l.Timestamp)
                .AsQueryable();

            if (!string.IsNullOrEmpty(eventType))
            {
                query = query.Where(l => l.EventType == eventType);
            }

            if (!string.IsNullOrWhiteSpace(search))
            {
                query = query.Where(l => l.Description.Contains(search) || (l.User != null && l.User.Email.Contains(search)));
            }

            var totalItems = await query.CountAsync();
            var items = await query
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return Results.Ok(new 
            {
                items,
                totalItems,
                page,
                pageSize,
                totalPages = (int)Math.Ceiling(totalItems / (double)pageSize)
            });
        });
    }

    public record CreateClientRequest(
        string DisplayName,
        string Audience,
        List<string>? RedirectUris,
        List<string>? AllowedScopes,
        bool IsTrustedForExchange = false,
        bool IsDefault = false);
}

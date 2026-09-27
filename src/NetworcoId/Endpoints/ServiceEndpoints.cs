using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using NetworcoId.Models.Auth;
using NetworcoId.Services;

namespace NetworcoId.Endpoints;

/// <summary>
/// Server-to-server API for networco-app, authenticated with a shared key in the
/// <c>X-Service-Key</c> header (<see cref="NetworcoIdConfig.ServiceApiKey"/>, env
/// SERVICE_API_KEY). Used by the account-deletion flow: a deletion request
/// deactivates the IdP account, cancelling it reactivates, carrying it out deletes.
/// </summary>
public static class ServiceEndpoints
{
    public const string ServiceKeyHeader = "X-Service-Key";

    public record LifecycleRequest(string? Reason);

    public static void MapServiceApi(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/service")
            .AddEndpointFilter(async (ctx, next) =>
            {
                var config = ctx.HttpContext.RequestServices.GetRequiredService<NetworcoIdConfig>();
                var presented = ctx.HttpContext.Request.Headers[ServiceKeyHeader].ToString();
                return IsValidKey(config.ServiceApiKey, presented)
                    ? await next(ctx)
                    : Results.Unauthorized();
            });

        group.MapPost("/users/{id:guid}/deactivate", async (Guid id, [FromBody] LifecycleRequest? request, IAccountLifecycleService lifecycle) =>
            await lifecycle.DeactivateAsync(id, ReasonOf(request)) ? Results.NoContent() : Results.NotFound());

        group.MapPost("/users/{id:guid}/reactivate", async (Guid id, [FromBody] LifecycleRequest? request, IAccountLifecycleService lifecycle) =>
            await lifecycle.ReactivateAsync(id, ReasonOf(request)) ? Results.NoContent() : Results.NotFound());

        // Idempotent: an already-deleted user is a success, so the caller can retry freely.
        group.MapDelete("/users/{id:guid}", async (Guid id, [FromQuery] string? reason, IAccountLifecycleService lifecycle) =>
        {
            await lifecycle.DeleteAsync(id, string.IsNullOrWhiteSpace(reason) ? "networco-app" : reason);
            return Results.NoContent();
        });
    }

    private static string ReasonOf(LifecycleRequest? request) =>
        string.IsNullOrWhiteSpace(request?.Reason) ? "networco-app" : request.Reason;

    /// <summary>Constant-time compare; an unconfigured key rejects everything.</summary>
    internal static bool IsValidKey(string? configured, string? presented)
    {
        if (string.IsNullOrEmpty(configured) || string.IsNullOrEmpty(presented)) return false;
        return CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(configured)),
            SHA256.HashData(Encoding.UTF8.GetBytes(presented)));
    }
}

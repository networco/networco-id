using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Services.Audit;

namespace NetworcoId.Services;

/// <summary>
/// Deactivating, reactivating and permanently deleting accounts. Used by the admin UI
/// and by networco-app's account-deletion flow (via <c>/api/service/users/*</c>):
/// a deletion request deactivates the account at once, and it is deleted when the
/// request is carried out (at the latest 30 days later).
/// </summary>
public interface IAccountLifecycleService
{
    /// <summary>Blocks login and revokes every refresh token. False if the user doesn't exist.</summary>
    Task<bool> DeactivateAsync(Guid userId, string reason);

    /// <summary>Lets the user log in again. False if the user doesn't exist.</summary>
    Task<bool> ReactivateAsync(Guid userId, string reason);

    /// <summary>
    /// Deletes the user and everything cascading from it (credentials, external logins,
    /// refresh tokens), and scrubs their personal data from the audit log. False if the
    /// user doesn't exist (already deleted).
    /// </summary>
    Task<bool> DeleteAsync(Guid userId, string reason);
}

public class AccountLifecycleService(
    AuthDbContext context,
    IAuthService authService,
    IAuditService auditService,
    ILogger<AccountLifecycleService> logger) : IAccountLifecycleService
{
    private const string RedactedDescription = "[fjernet: brukeren er slettet]";

    public async Task<bool> DeactivateAsync(Guid userId, string reason)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return false;

        if (user.IsActive)
        {
            user.IsActive = false;
            await context.SaveChangesAsync();
        }

        // Always revoke, even if already inactive — a retry must still cut off renewal.
        await authService.InvalidateActiveSessionsAsync(userId);
        await auditService.LogAsync("UserDeactivated", $"User deactivated: {reason}", userId);
        logger.LogInformation("Deactivated user {UserId}: {Reason}", userId, reason);
        return true;
    }

    public async Task<bool> ReactivateAsync(Guid userId, string reason)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return false;

        if (!user.IsActive)
        {
            user.IsActive = true;
            await context.SaveChangesAsync();
        }

        await auditService.LogAsync("UserReactivated", $"User reactivated: {reason}", userId);
        logger.LogInformation("Reactivated user {UserId}: {Reason}", userId, reason);
        return true;
    }

    public async Task<bool> DeleteAsync(Guid userId, string reason)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return false;

        // The audit log outlives the user (FK is SetNull) and its free text carries the
        // email, IP and user agent. Scrub the user's own rows, plus rows that only name
        // them by an identifier — a failed login logs whatever was typed (email, national
        // id or phone) with no user id.
        var logs = await context.AuditLogs.Where(l => l.UserId == userId).ToListAsync();
        foreach (var identifier in IdentifiersOf(user))
        {
            var lowered = identifier.ToLower();
            var candidates = await context.AuditLogs
                .Where(l => l.UserId != userId && l.Description.ToLower().Contains(lowered))
                .ToListAsync();
            // Contains is only a pre-filter: "ola@x.no" is also inside "kola@x.no", and
            // another user's audit trail must not be wiped.
            logs.AddRange(candidates.Where(l => MentionsIdentifier(l.Description, identifier)));
        }
        logs = logs.DistinctBy(l => l.Id).ToList();
        foreach (var log in logs)
        {
            log.Description = RedactedDescription;
            log.IpAddress = null;
            log.UserAgent = null;
            log.Metadata = null;
        }

        // The FKs cascade in Postgres, but removing the dependents explicitly keeps the
        // delete complete regardless of provider (and of any future FK change).
        context.RefreshTokens.RemoveRange(await context.RefreshTokens.Where(t => t.UserId == userId).ToListAsync());
        context.UserExternalLogins.RemoveRange(await context.UserExternalLogins.Where(l => l.UserId == userId).ToListAsync());
        context.UserCredentials.RemoveRange(await context.UserCredentials.Where(c => c.Id == userId).ToListAsync());
        context.Users.Remove(user);
        await context.SaveChangesAsync();

        // No email or name here — this row must not re-introduce what was just removed.
        await auditService.LogAsync("UserDeleted", $"User {userId} deleted: {reason}");
        logger.LogInformation("Deleted user {UserId} ({LogCount} audit rows scrubbed): {Reason}", userId, logs.Count, reason);
        return true;
    }

    private static IEnumerable<string> IdentifiersOf(NetworcoId.Models.Entities.UserEntity user) =>
        new[] { user.Email, user.NationalId, user.PhoneNumber }
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The identifier as a whole token: not preceded by a character that could belong to
    /// it (letters, digits, <c>.+-_</c>), and not followed by one (a trailing sentence
    /// period is fine, <c>.uk</c> is not).
    /// </summary>
    public static bool MentionsIdentifier(string text, string identifier) =>
        Regex.IsMatch(
            text,
            $@"(?<![\w.+\-]){Regex.Escape(identifier)}(?![\w\-]|\.\w)",
            RegexOptions.IgnoreCase);
}

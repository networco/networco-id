using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;

namespace NetworcoId.Workers;

/// <summary>
/// Background worker that periodically cleans up expired IP lockouts from the database.
/// </summary>
public class LockoutCleanupWorker(
    IServiceProvider serviceProvider,
    ILogger<LockoutCleanupWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("LockoutCleanupWorker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

                var expiredLockouts = await dbContext.IpLockouts
                    .Where(l => l.LockedUntil < DateTimeOffset.UtcNow && l.FailedAttempts >= 10) // Clean up long-expired or settled records
                    .ToListAsync(stoppingToken);

                // Alternatively, just clean up everything that hasn't been touched in 24 hours
                var cutoff = DateTimeOffset.UtcNow.AddDays(-1);
                var staleRecords = await dbContext.IpLockouts
                    .Where(l => l.LastAttemptAt < cutoff && (l.LockedUntil == null || l.LockedUntil < DateTimeOffset.UtcNow))
                    .ToListAsync(stoppingToken);

                if (staleRecords.Any())
                {
                    logger.LogInformation("Cleaning up {Count} stale IP lockout records.", staleRecords.Count);
                    dbContext.IpLockouts.RemoveRange(staleRecords);
                    await dbContext.SaveChangesAsync(stoppingToken);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred while cleaning up IP lockouts.");
            }

            // Run once per hour
            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
        }
    }
}

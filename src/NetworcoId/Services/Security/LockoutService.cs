using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;

namespace NetworcoId.Services.Security;

/// <summary>
/// Implementation of ILockoutService using a hybrid approach of Local Memory Cache and PostgreSQL.
/// </summary>
public class LockoutService(
    AuthDbContext dbContext, 
    IMemoryCache cache, 
    NetworcoIdConfig config,
    ILogger<LockoutService> logger) : ILockoutService
{
    private const string CachePrefix = "ip_lockout_";

    public async Task<bool> IsLockedAsync(string ipAddress)
    {
        // 1. Check Local Cache (Fastest)
        if (cache.TryGetValue(GetCacheKey(ipAddress), out DateTimeOffset lockedUntil))
        {
            if (lockedUntil > DateTimeOffset.UtcNow)
            {
                return true;
            }
            cache.Remove(GetCacheKey(ipAddress));
        }

        // 2. Check Database (Distributed Consistency)
        var lockout = await dbContext.IpLockouts
            .AsNoTracking()
            .FirstOrDefaultAsync(l => l.IpAddress == ipAddress);

        if (lockout?.LockedUntil > DateTimeOffset.UtcNow)
        {
            // Sync local cache
            cache.Set(GetCacheKey(ipAddress), lockout.LockedUntil.Value, TimeSpan.FromMinutes(5));
            return true;
        }

        return false;
    }

    public async Task RecordFailureAsync(string ipAddress)
    {
        var lockout = await dbContext.IpLockouts
            .FirstOrDefaultAsync(l => l.IpAddress == ipAddress);

        if (lockout == null)
        {
            lockout = new IpLockoutEntity
            {
                IpAddress = ipAddress,
                FailedAttempts = 1,
                LastAttemptAt = DateTimeOffset.UtcNow
            };
            dbContext.IpLockouts.Add(lockout);
        }
        else
        {
            lockout.FailedAttempts++;
            lockout.LastAttemptAt = DateTimeOffset.UtcNow;
        }

        if (lockout.FailedAttempts >= config.IpLockoutMaxFailures)
        {
            var until = DateTimeOffset.UtcNow.AddMinutes(config.IpLockoutDurationMinutes);
            lockout.LockedUntil = until;
            
            // Set in local cache
            cache.Set(GetCacheKey(ipAddress), until, TimeSpan.FromMinutes(config.IpLockoutDurationMinutes));
            
            logger.LogWarning("IP {IpAddress} locked out until {Until} after {Attempts} failed attempts.", 
                ipAddress, until, lockout.FailedAttempts);
        }

        await dbContext.SaveChangesAsync();
    }

    public async Task ResetAsync(string ipAddress)
    {
        var lockout = await dbContext.IpLockouts
            .FirstOrDefaultAsync(l => l.IpAddress == ipAddress);

        if (lockout != null)
        {
            dbContext.IpLockouts.Remove(lockout);
            await dbContext.SaveChangesAsync();
        }

        cache.Remove(GetCacheKey(ipAddress));
    }

    private static string GetCacheKey(string ip) => $"{CachePrefix}{ip}";
}

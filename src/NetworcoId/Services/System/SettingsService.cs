using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace NetworcoId.Services.System;

public interface ISettingsService
{
    Task LoadSettingsAsync();
    Task SaveSettingAsync(string key, string value);
    Task SaveSettingsAsync(NetworcoIdConfig config);
}

public class SettingsService : ISettingsService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly NetworcoIdConfig _config;
    private readonly ILogger<SettingsService> _logger;

    public SettingsService(
        IServiceProvider serviceProvider,
        NetworcoIdConfig config,
        ILogger<SettingsService> logger)
    {
        _serviceProvider = serviceProvider;
        _config = config;
        _logger = logger;
    }

    public async Task LoadSettingsAsync()
    {
        using var scope = _serviceProvider.CreateScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AuthDbContext>>();
        using var context = await contextFactory.CreateDbContextAsync();
        var settings = await context.SystemSettings.ToListAsync();

        foreach (var setting in settings)
        {
            ApplySetting(setting.Key, setting.Value);
        }
    }

    public async Task SaveSettingAsync(string key, string value)
    {
        using var scope = _serviceProvider.CreateScope();
        var contextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AuthDbContext>>();
        using var context = await contextFactory.CreateDbContextAsync();
        
        var setting = await context.SystemSettings.FirstOrDefaultAsync(s => s.Key == key);
        if (setting == null)
        {
            setting = new SystemSettingEntity { Key = key, Value = value, UpdatedAt = DateTimeOffset.UtcNow };
            context.SystemSettings.Add(setting);
        }
        else
        {
            setting.Value = value;
            setting.UpdatedAt = DateTimeOffset.UtcNow;
        }

        await context.SaveChangesAsync();
        ApplySetting(key, value);
    }

    public async Task SaveSettingsAsync(NetworcoIdConfig config)
    {
        // For simplicity, we save the security settings we care about
        await SaveSettingAsync(nameof(config.MinPasswordLength), config.MinPasswordLength.ToString());
        await SaveSettingAsync(nameof(config.RequireDigit), config.RequireDigit.ToString());
        await SaveSettingAsync(nameof(config.RequireUppercase), config.RequireUppercase.ToString());
        await SaveSettingAsync(nameof(config.RequireLowercase), config.RequireLowercase.ToString());
        await SaveSettingAsync(nameof(config.RequireNonAlphanumeric), config.RequireNonAlphanumeric.ToString());
        await SaveSettingAsync(nameof(config.MaxFailedLoginAttempts), config.MaxFailedLoginAttempts.ToString());
        await SaveSettingAsync(nameof(config.LockoutDurationMinutes), config.LockoutDurationMinutes.ToString());
        await SaveSettingAsync(nameof(config.AccessTokenExpirationMinutes), config.AccessTokenExpirationMinutes.ToString());
        await SaveSettingAsync(nameof(config.RefreshTokenExpirationDays), config.RefreshTokenExpirationDays.ToString());
        
        // Brute Force & Rate Limiting
        await SaveSettingAsync(nameof(config.IpLockoutMaxFailures), config.IpLockoutMaxFailures.ToString());
        await SaveSettingAsync(nameof(config.IpLockoutDurationMinutes), config.IpLockoutDurationMinutes.ToString());
        await SaveSettingAsync(nameof(config.AdminRateLimitPermit), config.AdminRateLimitPermit.ToString());
        await SaveSettingAsync(nameof(config.AdminRateLimitWindowSeconds), config.AdminRateLimitWindowSeconds.ToString());
        await SaveSettingAsync(nameof(config.AuthRateLimitPermit), config.AuthRateLimitPermit.ToString());
        await SaveSettingAsync(nameof(config.AuthRateLimitWindowSeconds), config.AuthRateLimitWindowSeconds.ToString());
    }

    private void ApplySetting(string key, string value)
    {
        try
        {
            switch (key)
            {
                case nameof(_config.MinPasswordLength):
                    if (int.TryParse(value, out var minLen)) _config.MinPasswordLength = minLen;
                    break;
                case nameof(_config.RequireDigit):
                    if (bool.TryParse(value, out var reqDigit)) _config.RequireDigit = reqDigit;
                    break;
                case nameof(_config.RequireUppercase):
                    if (bool.TryParse(value, out var reqUpper)) _config.RequireUppercase = reqUpper;
                    break;
                case nameof(_config.RequireLowercase):
                    if (bool.TryParse(value, out var reqLower)) _config.RequireLowercase = reqLower;
                    break;
                case nameof(_config.RequireNonAlphanumeric):
                    if (bool.TryParse(value, out var reqNonAlpha)) _config.RequireNonAlphanumeric = reqNonAlpha;
                    break;
                case nameof(_config.MaxFailedLoginAttempts):
                    if (int.TryParse(value, out var maxAttempts)) _config.MaxFailedLoginAttempts = maxAttempts;
                    break;
                case nameof(_config.LockoutDurationMinutes):
                    if (int.TryParse(value, out var lockoutMins)) _config.LockoutDurationMinutes = lockoutMins;
                    break;
                case nameof(_config.AccessTokenExpirationMinutes):
                    if (int.TryParse(value, out var accessExp)) _config.AccessTokenExpirationMinutes = accessExp;
                    break;
                case nameof(_config.RefreshTokenExpirationDays):
                    if (int.TryParse(value, out var refreshExp)) _config.RefreshTokenExpirationDays = refreshExp;
                    break;
                case nameof(_config.IpLockoutMaxFailures):
                    if (int.TryParse(value, out var ipMax)) _config.IpLockoutMaxFailures = ipMax;
                    break;
                case nameof(_config.IpLockoutDurationMinutes):
                    if (int.TryParse(value, out var ipDur)) _config.IpLockoutDurationMinutes = ipDur;
                    break;
                case nameof(_config.AdminRateLimitPermit):
                    if (int.TryParse(value, out var admPerm)) _config.AdminRateLimitPermit = admPerm;
                    break;
                case nameof(_config.AdminRateLimitWindowSeconds):
                    if (int.TryParse(value, out var admWin)) _config.AdminRateLimitWindowSeconds = admWin;
                    break;
                case nameof(_config.AuthRateLimitPermit):
                    if (int.TryParse(value, out var authPerm)) _config.AuthRateLimitPermit = authPerm;
                    break;
                case nameof(_config.AuthRateLimitWindowSeconds):
                    if (int.TryParse(value, out var authWin)) _config.AuthRateLimitWindowSeconds = authWin;
                    break;
                case "System:ManagementClientId":
                    _config.SystemManagementClientId = value;
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error applying setting {Key} with value {Value}", key, value);
        }
    }
}

using NetworcoId.Services.System;

namespace NetworcoId.Configuration;

/// <summary>
/// Hosted service that loads system settings from the database into memory on startup.
/// This runs before the main application logic but after the host is built.
/// </summary>
public class SettingsInitialLoader : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SettingsInitialLoader> _logger;

    public SettingsInitialLoader(IServiceProvider serviceProvider, ILogger<SettingsInitialLoader> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Loading system settings from database...");
        
        using var scope = _serviceProvider.CreateScope();
        var settingsService = scope.ServiceProvider.GetRequiredService<ISettingsService>();
        
        try
        {
            await settingsService.LoadSettingsAsync();
            _logger.LogInformation("System settings loaded successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load system settings from database on startup.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

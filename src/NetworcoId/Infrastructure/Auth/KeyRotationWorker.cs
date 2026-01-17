using NetworcoId.Infrastructure.Auth;

namespace NetworcoId.Workers;

/// <summary>
/// Background worker for rotating signing keys.
/// </summary>
public class KeyRotationWorker : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<KeyRotationWorker> _logger;

    public KeyRotationWorker(
        IServiceProvider serviceProvider,
        ILogger<KeyRotationWorker> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("KeyRotationWorker started.");

        // Initial check on startup
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var keyManager = scope.ServiceProvider.GetRequiredService<IKeyManagementService>();
            
            // 1. Ensure active key exists
            await keyManager.EnsureActiveKeyAsync(stoppingToken);
            
            // 2. Run rotation logic immediately in case we missed a window while down
            await keyManager.RotateKeysAsync(stoppingToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during initial key check.");
        }

        // Run periodically
        using var timer = new PeriodicTimer(TimeSpan.FromHours(6));
        
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                _logger.LogInformation("Running key rotation check...");
                using var scope = _serviceProvider.CreateScope();
                var keyManager = scope.ServiceProvider.GetRequiredService<IKeyManagementService>();
                await keyManager.RotateKeysAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during key rotation check.");
            }
        }
    }
}

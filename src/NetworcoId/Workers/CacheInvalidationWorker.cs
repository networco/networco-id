using NetworcoId.Infrastructure.Auth;

namespace NetworcoId.Workers;

/// <summary>
/// Background worker that listens for NATS events to invalidate local caches.
/// </summary>
public class CacheInvalidationWorker : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<CacheInvalidationWorker> _logger;

    public CacheInvalidationWorker(
        IServiceProvider serviceProvider,
        ILogger<CacheInvalidationWorker> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CacheInvalidationWorker started.");

        try
        {
            using var scope = _serviceProvider.CreateScope();
            var jwtService = scope.ServiceProvider.GetRequiredService<IJwtService>();
            
            // This is a long-running listening task
            await jwtService.ListenForKeyRotationEventsAsync(stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Graceful shutdown
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fatal error in CacheInvalidationWorker.");
        }
    }
}

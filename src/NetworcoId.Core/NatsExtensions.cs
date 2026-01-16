using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NATS.Client.Serializers.Json;
using NetworcoId.Core.Models;

namespace NetworcoId.Core;

public static class NatsExtensions
{
    public static IServiceCollection AddNatsMessaging(this IServiceCollection services, IConfiguration configuration, string clientName)
    {
        var natsSection = configuration.GetSection("Nats");
        var url = configuration["NATS_URL"] ?? natsSection["Url"] ?? "nats://localhost:4222";
        
        var opts = new NatsOpts
        {
            Url = url,
            Name = clientName,
            SerializerRegistry = NatsJsonSerializerRegistry.Default
        };

        services.AddSingleton<INatsConnection>(_ => new NatsConnection(opts));

        return services;
    }

    public static async Task ProvisionStreamsAsync(this INatsConnection nats, ILogger logger)
    {
        try
        {
            var js = new NatsJSContext(nats);
            
            // CLEANUP: If we renamed the stream, the old ones might still own the subjects.
            // We attempt to delete the old generic names to "free" the subjects for the new stream.
            var legacyStreams = new[] { "NETWORCOID", "NETWORCOID_IDENTITY" };
            foreach (var legacy in legacyStreams)
            {
                try
                {
                    await js.DeleteStreamAsync(legacy);
                    logger.LogInformation("Cleaned up legacy NATS stream: {Stream}", legacy);
                }
                catch { /* Ignore if doesn't exist */ }
            }

            var streamConfig = new StreamConfig(
                name: NetworcoIdSubjects.StreamName,
                subjects: new[] { 
                    NetworcoIdSubjects.EmailVerify, 
                    NetworcoIdSubjects.EmailOtp,
                    NetworcoIdSubjects.PasswordReset,
                    NetworcoIdSubjects.EmailNotification
                })
            {
                Retention = StreamConfigRetention.Workqueue,
                Storage = StreamConfigStorage.File,
                Discard = StreamConfigDiscard.Old,
                DuplicateWindow = TimeSpan.FromMinutes(2)
            };

            try 
            {
                await js.CreateStreamAsync(streamConfig);
                logger.LogInformation("NATS Stream {Stream} (WorkQueue) provisioned", NetworcoIdSubjects.StreamName);
            }
            catch (NatsJSApiException ex) when (ex.Message.Contains("already has stream") || ex.Message.Contains("already exists"))
            {
                logger.LogInformation("NATS Stream {Stream} already exists. Updating configuration...", NetworcoIdSubjects.StreamName);
                await js.UpdateStreamAsync(streamConfig);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "CRITICAL: Failed to provision NATS JetStream stream {Stream}. Error: {Message}", NetworcoIdSubjects.StreamName, ex.Message);
            throw; 
        }
    }
}

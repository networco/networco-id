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

            try 
            {
                await js.CreateStreamAsync(new StreamConfig(
                    name: NetworcoIdSubjects.StreamName,
                    subjects: new[] { 
                        NetworcoIdSubjects.EmailVerify, 
                        NetworcoIdSubjects.EmailOtp,
                        NetworcoIdSubjects.EmailNotification
                    })
                {
                    Retention = StreamConfigRetention.Workqueue,
                    Storage = StreamConfigStorage.File,
                    Discard = StreamConfigDiscard.Old
                });
                logger.LogInformation("NATS Stream {Stream} (WorkQueue) provisioned", NetworcoIdSubjects.StreamName);
            }
            catch (Exception ex) when (ex.Message.Contains("already in use"))
            {
                logger.LogInformation("NATS Stream {Stream} already exists", NetworcoIdSubjects.StreamName);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to provision NATS JetStream streams. Ensure JetStream is enabled on the NATS server (-js).");
        }
    }
}

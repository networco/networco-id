using NATS.Client.Core;
using NetworcoId.Core;

namespace NetworcoId.Configuration;

public static class NatsConfiguration
{
    public static IServiceCollection AddNatsMessaging(this IServiceCollection services, IConfiguration configuration)
    {
        return NetworcoId.Core.NatsExtensions.AddNatsMessaging(services, configuration, "NetworcoId");
    }
}

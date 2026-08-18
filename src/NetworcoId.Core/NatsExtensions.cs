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
            Name = clientName
        };

        services.AddSingleton<INatsConnection>(_ => new NatsConnection(opts));

        return services;
    }

    /// <summary>
    /// Ensures the identity stream exists with the desired configuration.
    /// </summary>
    /// <param name="throwOnFailure">
    /// When false (the default) a provisioning failure is logged and swallowed, and the
    /// method returns false. The IdP relies on that: it serves every OAuth/OIDC flow
    /// without JetStream, so a stream it cannot provision must not stop it from starting.
    /// It used to rethrow into Program.Main, and a single drifted field (NumReplicas,
    /// after NATS_STREAM_REPLICAS was set on an environment whose stream already
    /// existed at another factor) took the whole identity provider down in a crash loop
    /// that no restart could clear.
    /// Callers whose entire job IS the stream — the worker's consume loop — pass true and
    /// retry on their own schedule, which is a better retry than CrashLoopBackOff.
    /// </param>
    /// <returns>True when the stream is provisioned and matches the desired config.</returns>
    public static async Task<bool> ProvisionStreamsAsync(this INatsConnection nats, ILogger logger, bool throwOnFailure = false)
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

            var streamConfig = BuildStreamConfig();

            try
            {
                await js.CreateStreamAsync(streamConfig);
                logger.LogInformation("NATS Stream {Stream} (WorkQueue) provisioned", NetworcoIdSubjects.StreamName);
            }
            catch (NatsJSApiException ex) when (IsAlreadyExists(ex))
            {
                // "already in use with a different configuration" belongs here too. It
                // did not match the old filter, so a drifted stream fell through to the
                // outer catch and was rethrown as fatal instead of being updated.
                logger.LogInformation("NATS Stream {Stream} already exists. Updating configuration...", NetworcoIdSubjects.StreamName);
                await js.UpdateStreamAsync(streamConfig);
            }

            return true;
        }
        catch (Exception ex)
        {
            // Name the fields that differ. The server only says "already in use with a
            // different configuration", which leaves whoever is paged reading deploy
            // diffs to guess which field moved.
            await LogConfigDriftAsync(nats, logger, ex);

            if (throwOnFailure)
            {
                logger.LogError(ex, "Failed to provision NATS JetStream stream {Stream}. Error: {Message}", NetworcoIdSubjects.StreamName, ex.Message);
                throw;
            }

            logger.LogError(ex,
                "Failed to provision NATS JetStream stream {Stream}, continuing startup without it. " +
                "Queued email will not be delivered until this is resolved. Error: {Message}",
                NetworcoIdSubjects.StreamName, ex.Message);
            return false;
        }
    }

    /// <summary>The stream configuration this service wants. Single source of truth so the
    /// drift report cannot describe a different "desired" than the one we tried to apply.</summary>
    public static StreamConfig BuildStreamConfig() =>
        new(name: NetworcoIdSubjects.StreamName,
            subjects: new[]
            {
                NetworcoIdSubjects.EmailVerify,
                NetworcoIdSubjects.EmailOtp,
                NetworcoIdSubjects.PasswordReset,
                NetworcoIdSubjects.EmailNotification
            })
        {
            Retention = StreamConfigRetention.Workqueue,
            Storage = StreamConfigStorage.File,
            Discard = StreamConfigDiscard.Old,
            DuplicateWindow = TimeSpan.FromMinutes(2),
            NumReplicas = GetStreamReplicas() // 3 in prod (HA); 1 on single-node test
        };

    /// <summary>The server wording for "this stream is already here" has several forms.</summary>
    private static bool IsAlreadyExists(NatsJSApiException ex) =>
        ex.Message.Contains("already has stream", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("already in use", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Best-effort: read back what the server actually holds and report how it differs
    /// from what we asked for. Never throws — this runs on an error path.
    /// </summary>
    private static async Task LogConfigDriftAsync(INatsConnection nats, ILogger logger, Exception cause)
    {
        if (cause is not NatsJSApiException api || !IsAlreadyExists(api))
        {
            return;
        }

        try
        {
            var js = new NatsJSContext(nats);
            var existing = await js.GetStreamAsync(NetworcoIdSubjects.StreamName);
            var drift = DescribeConfigDrift(BuildStreamConfig(), existing.Info.Config);

            if (drift.Count > 0)
            {
                logger.LogError(
                    "NATS Stream {Stream} exists with a different configuration. Differences (desired vs existing): {Drift}",
                    NetworcoIdSubjects.StreamName, string.Join("; ", drift));
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not read back NATS stream {Stream} to report configuration drift", NetworcoIdSubjects.StreamName);
        }
    }

    /// <summary>
    /// Field-by-field comparison of the fields this provisioner sets. Pure, so the
    /// reporting can be tested without a NATS server.
    /// </summary>
    public static IReadOnlyList<string> DescribeConfigDrift(StreamConfig desired, StreamConfig existing)
    {
        var drift = new List<string>();

        var desiredSubjects = desired.Subjects ?? Enumerable.Empty<string>();
        var existingSubjects = existing.Subjects ?? Enumerable.Empty<string>();
        if (!desiredSubjects.OrderBy(s => s, StringComparer.Ordinal)
                .SequenceEqual(existingSubjects.OrderBy(s => s, StringComparer.Ordinal), StringComparer.Ordinal))
        {
            drift.Add($"Subjects: [{string.Join(",", desiredSubjects)}] vs [{string.Join(",", existingSubjects)}]");
        }

        Compare("NumReplicas", desired.NumReplicas, existing.NumReplicas);
        Compare("Retention", desired.Retention, existing.Retention);
        Compare("Storage", desired.Storage, existing.Storage);
        Compare("Discard", desired.Discard, existing.Discard);
        Compare("DuplicateWindow", desired.DuplicateWindow, existing.DuplicateWindow);

        return drift;

        void Compare<T>(string field, T desiredValue, T existingValue)
        {
            if (!EqualityComparer<T>.Default.Equals(desiredValue, existingValue))
            {
                drift.Add($"{field}: {desiredValue} vs {existingValue}");
            }
        }
    }

    /// <summary>
    /// JetStream replica factor for streams/KV. Defaults to 3 (the prod 3-node HA
    /// cluster). Single-node environments (e.g. the test cluster) set
    /// NATS_STREAM_REPLICAS=1 — a lone server can only host R=1, so R=3 fails with
    /// "replicas &gt; peers".
    /// </summary>
    public static int GetStreamReplicas()
    {
        var raw = Environment.GetEnvironmentVariable("NATS_STREAM_REPLICAS");
        return int.TryParse(raw, out var n) && n >= 1 ? n : 3;
    }
}

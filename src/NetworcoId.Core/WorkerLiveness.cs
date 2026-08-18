namespace NetworcoId.Core;

/// <summary>
/// The contract between the worker and its Kubernetes liveness probe.
///
/// The worker serves no HTTP, so the probe cannot call an endpoint — it stats a file the
/// consume loop refreshes while a consumer is established. That makes the file path a
/// coupling between code and manifest: point them at different paths and the probe watches
/// something nothing ever writes, so a perfectly healthy worker restarts every few minutes
/// forever. These constants exist so both sides name the same thing, and so a test can
/// assert the deployment manifest still agrees with the code.
/// </summary>
public static class WorkerLiveness
{
    /// <summary>Environment variable the deployment uses to override the path.</summary>
    public const string EnvVarName = "WORKER_LIVENESS_FILE";

    /// <summary>Path used when the environment variable is unset.</summary>
    public const string DefaultPath = "/tmp/networcoid-worker-alive";

    /// <summary>
    /// How often the worker refreshes the file while it is healthy.
    ///
    /// Lives here rather than in the worker because it is half of a coupling: the probe
    /// kills the pod once the file is older than <see cref="StaleAfter"/>, and this timer
    /// is the only thing refreshing it on an idle worker. Raising this alone — an obvious
    /// tidy-up, since it also controls how often the heartbeat line is logged — would make
    /// every HEALTHY worker miss the deadline and be restarted every few minutes.
    /// <c>MissedHeartbeatsTolerated</c> keeps the two in step, enforced by a test.
    /// </summary>
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMinutes(1);

    /// <summary>How many refreshes may be missed before the worker is considered dead.</summary>
    public const int MissedHeartbeatsTolerated = 3;

    /// <summary>
    /// How stale the file may get before the probe should consider the worker dead.
    /// Derived, so it cannot drift away from the refresh rate.
    /// </summary>
    public static readonly TimeSpan StaleAfter = HeartbeatInterval * MissedHeartbeatsTolerated;

    /// <summary>Resolved path: the environment override when set, the default otherwise.</summary>
    public static string ResolvePath() =>
        Environment.GetEnvironmentVariable(EnvVarName) is { Length: > 0 } configured
            ? configured
            : DefaultPath;
}

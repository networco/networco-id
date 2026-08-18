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
    /// How stale the file may get before the probe should consider the worker dead.
    /// Three missed heartbeats — the worker refreshes once a minute.
    /// </summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(3);

    /// <summary>Resolved path: the environment override when set, the default otherwise.</summary>
    public static string ResolvePath() =>
        Environment.GetEnvironmentVariable(EnvVarName) is { Length: > 0 } configured
            ? configured
            : DefaultPath;
}

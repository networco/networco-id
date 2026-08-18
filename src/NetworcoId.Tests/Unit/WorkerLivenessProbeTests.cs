using System.Text.RegularExpressions;
using NetworcoId.Core;
using Xunit;

namespace NetworcoId.Tests.Unit;

/// <summary>
/// The worker's liveness probe stats a file the consume loop refreshes — it serves no HTTP,
/// so there is no endpoint to call. That makes the path a coupling between C# and YAML which
/// nothing else checks: point them at different files and the probe watches something nobody
/// writes, so a healthy worker restarts every few minutes forever, and a dead one still looks
/// no different. These tests hold the two sides together.
/// </summary>
public class WorkerLivenessProbeTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "deploy", "k3s")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir); // the manifests must be findable from the test output dir
        return dir!.FullName;
    }

    private static string WorkerManifest() =>
        File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "k3s", "05-worker.yaml"));

    [Fact]
    public void Manifest_PointsTheProbeAtThePathTheWorkerWrites()
    {
        var manifest = WorkerManifest();

        var declared = Regex.Match(
            manifest,
            @"name:\s*" + Regex.Escape(WorkerLiveness.EnvVarName) + @"\s*\n\s*value:\s*(?<path>\S+)");

        Assert.True(declared.Success, $"{WorkerLiveness.EnvVarName} is not set in 05-worker.yaml");
        Assert.Equal(WorkerLiveness.DefaultPath, declared.Groups["path"].Value.Trim('"', '\''));
    }

    [Fact]
    public void Probe_ReadsThePathFromTheEnvironmentRatherThanHardcodingIt()
    {
        // If the command inlined a literal path, changing WORKER_LIVENESS_FILE would move
        // the file the worker writes without moving the file the probe checks.
        var manifest = WorkerManifest();
        Assert.Contains($"${WorkerLiveness.EnvVarName}", manifest);
    }

    [Fact]
    public void Probe_ToleratesAtLeastThreeMissedHeartbeats()
    {
        // The worker refreshes once a minute. A threshold at or below one interval would
        // restart the pod over a single slow tick.
        var manifest = WorkerManifest();

        var threshold = Regex.Match(manifest, @"-lt\s+(?<seconds>\d+)");
        Assert.True(threshold.Success, "liveness command has no staleness threshold");

        var seconds = int.Parse(threshold.Groups["seconds"].Value);
        Assert.Equal(WorkerLiveness.StaleAfter.TotalSeconds, seconds);
        Assert.True(seconds >= 180, $"threshold {seconds}s is too tight for a 60s heartbeat");
    }

    [Fact]
    public void ResolvePath_PrefersTheEnvironmentOverride()
    {
        var previous = Environment.GetEnvironmentVariable(WorkerLiveness.EnvVarName);
        try
        {
            Environment.SetEnvironmentVariable(WorkerLiveness.EnvVarName, "/var/run/custom-alive");
            Assert.Equal("/var/run/custom-alive", WorkerLiveness.ResolvePath());
        }
        finally
        {
            Environment.SetEnvironmentVariable(WorkerLiveness.EnvVarName, previous);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ResolvePath_FallsBackToTheDefault(string? configured)
    {
        var previous = Environment.GetEnvironmentVariable(WorkerLiveness.EnvVarName);
        try
        {
            Environment.SetEnvironmentVariable(WorkerLiveness.EnvVarName, configured);
            Assert.Equal(WorkerLiveness.DefaultPath, WorkerLiveness.ResolvePath());
        }
        finally
        {
            Environment.SetEnvironmentVariable(WorkerLiveness.EnvVarName, previous);
        }
    }

    [Fact]
    public void ApiManifest_KeepsTheStartupProbeLongerThanTheMigrationRetryBudget()
    {
        // Program.cs retries migrations 10x with a 5s backoff before the app serves. If the
        // startup budget were shorter, a cold database would get the pod killed mid-migration
        // and it would never finish starting.
        var api = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "k3s", "04-api.yaml"));

        var startup = Regex.Match(api,
            @"startupProbe:.*?periodSeconds:\s*(?<period>\d+).*?failureThreshold:\s*(?<threshold>\d+)",
            RegexOptions.Singleline);

        Assert.True(startup.Success, "04-api.yaml has no startupProbe");

        var budget = int.Parse(startup.Groups["period"].Value) * int.Parse(startup.Groups["threshold"].Value);
        Assert.True(budget >= 100, $"startup budget {budget}s is under the ~50s migration retry window plus bootstrap");
    }
}

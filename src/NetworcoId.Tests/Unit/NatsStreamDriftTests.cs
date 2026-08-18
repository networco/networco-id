using NATS.Client.JetStream.Models;
using NetworcoId.Core;
using NetworcoId.Core.Models;
using Xunit;

namespace NetworcoId.Tests.Unit;

/// <summary>
/// The drift report exists because of a production incident: setting
/// NATS_STREAM_REPLICAS on an environment whose stream already existed at another
/// replica factor made the server answer "stream name already in use with a different
/// configuration" — which names no field. The IdP rethrew that into Main and crash-looped,
/// and diagnosing it meant reading deploy diffs to guess which field had moved.
/// These tests pin the report that replaces the guessing.
/// </summary>
public class NatsStreamDriftTests
{
    private static StreamConfig Desired() => NatsExtensions.BuildStreamConfig();

    /// <summary>A copy of the desired config, so a test can move exactly one field.</summary>
    private static StreamConfig Like(StreamConfig source) =>
        new(name: source.Name ?? NetworcoIdSubjects.StreamName, subjects: source.Subjects?.ToList() ?? [])
        {
            Retention = source.Retention,
            Storage = source.Storage,
            Discard = source.Discard,
            DuplicateWindow = source.DuplicateWindow,
            NumReplicas = source.NumReplicas,
        };

    [Fact]
    public void IdenticalConfigs_ReportNoDrift()
    {
        Assert.Empty(NatsExtensions.DescribeConfigDrift(Desired(), Like(Desired())));
    }

    [Fact]
    public void ReplicaFactorDrift_IsNamedWithBothValues()
    {
        // The actual incident: desired 1 (NATS_STREAM_REPLICAS=1) against an existing 3.
        var desired = Desired();
        desired.NumReplicas = 1;

        var existing = Like(Desired());
        existing.NumReplicas = 3;

        var drift = NatsExtensions.DescribeConfigDrift(desired, existing);

        var line = Assert.Single(drift);
        Assert.Contains("NumReplicas", line);
        Assert.Contains("1", line);
        Assert.Contains("3", line);
    }

    [Fact]
    public void SubjectDrift_IsReported()
    {
        var existing = Like(Desired());
        existing.Subjects = [NetworcoIdSubjects.EmailVerify]; // stream missing three subjects

        var drift = NatsExtensions.DescribeConfigDrift(Desired(), existing);

        Assert.Contains(drift, d => d.StartsWith("Subjects:"));
    }

    [Fact]
    public void SubjectOrder_IsNotDrift()
    {
        // Subject order carries no meaning; reporting it would be noise on a real incident.
        var existing = Like(Desired());
        existing.Subjects = Desired().Subjects!.Reverse().ToList();

        Assert.Empty(NatsExtensions.DescribeConfigDrift(Desired(), existing));
    }

    [Fact]
    public void RetentionAndStorageDrift_AreReportedTogether()
    {
        var existing = Like(Desired());
        existing.Retention = StreamConfigRetention.Limits;
        existing.Storage = StreamConfigStorage.Memory;

        var drift = NatsExtensions.DescribeConfigDrift(Desired(), existing);

        Assert.Equal(2, drift.Count);
        Assert.Contains(drift, d => d.StartsWith("Retention:"));
        Assert.Contains(drift, d => d.StartsWith("Storage:"));
    }

    [Fact]
    public void DuplicateWindowDrift_IsReported()
    {
        var existing = Like(Desired());
        existing.DuplicateWindow = TimeSpan.FromMinutes(5);

        var drift = NatsExtensions.DescribeConfigDrift(Desired(), existing);

        Assert.Contains(drift, d => d.StartsWith("DuplicateWindow:"));
    }

    /// <summary>
    /// Regression guard. The drift report was originally gated on the exception carrying
    /// already-exists wording, which silenced it in the one case it existed for: on the
    /// drift path the create exception is consumed by the inner catch, and what surfaces
    /// is the follow-up UpdateStreamAsync failure, worded differently. Any re-introduced
    /// wording filter fails here.
    /// </summary>
    [Theory]
    [InlineData("stream name already in use with a different configuration")] // create path
    [InlineData("stream configuration update can not change number of replicas")] // update path
    [InlineData("nats: no responders available for request")] // NATS unreachable
    [InlineData("some message nobody predicted")]
    public void AnyProvisioningFailure_IsWorthReadingTheStreamBack(string message)
    {
        Assert.True(NatsExtensions.ShouldAttemptDriftReport(new InvalidOperationException(message)));
    }

    [Fact]
    public void Shutdown_DoesNotTriggerADriftReadBack()
    {
        // Cancellation is the process going away, not a configuration problem.
        Assert.False(NatsExtensions.ShouldAttemptDriftReport(new OperationCanceledException()));
    }

    [Theory]
    [InlineData(null, 3)]      // unset → prod's 3-node HA default
    [InlineData("", 3)]        // empty → same as unset; prod ran this way for months
    [InlineData("not-a-number", 3)]
    [InlineData("0", 3)]       // a stream needs at least one replica
    [InlineData("1", 1)]       // single-node test cluster
    [InlineData("3", 3)]
    public void ReplicaFactor_FallsBackToThreeUnlessValid(string? raw, int expected)
    {
        var previous = Environment.GetEnvironmentVariable("NATS_STREAM_REPLICAS");
        try
        {
            Environment.SetEnvironmentVariable("NATS_STREAM_REPLICAS", raw);
            Assert.Equal(expected, NatsExtensions.GetStreamReplicas());
        }
        finally
        {
            Environment.SetEnvironmentVariable("NATS_STREAM_REPLICAS", previous);
        }
    }
}

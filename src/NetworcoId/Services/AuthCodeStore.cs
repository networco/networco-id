using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;

namespace NetworcoId.Services;

/// <summary>
/// Persistent OAuth authorization-code session.
/// </summary>
public sealed record AuthCodeSession(
    string EmailOrNationalId,
    string RedirectUri,
    string? State,
    string? CodeChallenge,
    string? CodeChallengeMethod,
    string? Nonce,
    List<string> Scopes,
    DateTimeOffset? AuthTime,
    DateTimeOffset CreatedAt,
    DateTimeOffset? UsedAt);

/// <summary>
/// Stores short-lived OAuth authorization-code sessions outside of process
/// memory so they survive pod restarts and replicate across replicas. Backed
/// by a NATS JetStream KV bucket with a 5-minute TTL — matching the OAuth
/// code lifetime, so expired entries are reaped automatically.
/// </summary>
public interface IAuthCodeStore
{
    Task PutAsync(string code, AuthCodeSession session, CancellationToken ct = default);

    /// <summary>
    /// Atomically looks up a code, marks it as used, and returns the session.
    /// Returns null if the code is not found, was already used, or the
    /// compare-and-swap detects concurrent reuse. Atomicity is provided by
    /// NATS KV's revision-based <c>UpdateAsync</c>.
    /// </summary>
    Task<AuthCodeSession?> GetAndMarkUsedAsync(string code, CancellationToken ct = default);

    Task DeleteAsync(string code, CancellationToken ct = default);
}

public sealed class NatsKvAuthCodeStore : IAuthCodeStore
{
    /// <summary>How long an unused auth code stays valid in the bucket.</summary>
    public static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);

    private const string BucketName = "AUTH_CODES";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly INatsConnection _nats;
    private readonly ILogger<NatsKvAuthCodeStore> _logger;
    private INatsKVStore? _kv;
    private readonly SemaphoreSlim _initLock = new(1, 1);

    public NatsKvAuthCodeStore(INatsConnection nats, ILogger<NatsKvAuthCodeStore> logger)
    {
        _nats = nats;
        _logger = logger;
    }

    private async Task<INatsKVStore> GetStoreAsync(CancellationToken ct)
    {
        if (_kv is not null) return _kv;
        await _initLock.WaitAsync(ct);
        try
        {
            if (_kv is not null) return _kv;
            var js = new NatsJSContext(_nats);
            var kv = new NatsKVContext(js);
            _kv = await kv.CreateOrUpdateStoreAsync(new NatsKVConfig(BucketName)
            {
                MaxAge = CodeLifetime,
                Description = "OAuth authorization codes — short-lived single-use sessions",
                History = 1,
            }, ct);
            _logger.LogInformation("AuthCodeStore: bucket {Bucket} ready (TTL {Ttl}s)", BucketName, CodeLifetime.TotalSeconds);
            return _kv;
        }
        finally
        {
            _initLock.Release();
        }
    }

    public async Task PutAsync(string code, AuthCodeSession session, CancellationToken ct = default)
    {
        var kv = await GetStoreAsync(ct);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(session, JsonOpts);
        await kv.PutAsync(code, bytes, cancellationToken: ct);
    }

    public async Task<AuthCodeSession?> GetAndMarkUsedAsync(string code, CancellationToken ct = default)
    {
        var kv = await GetStoreAsync(ct);

        NatsKVEntry<byte[]> entry;
        try
        {
            entry = await kv.GetEntryAsync<byte[]>(code, cancellationToken: ct);
        }
        catch (NatsKVKeyNotFoundException)
        {
            return null;
        }
        catch (NatsKVKeyDeletedException)
        {
            return null;
        }

        if (entry.Value is null) return null;

        AuthCodeSession? session;
        try
        {
            session = JsonSerializer.Deserialize<AuthCodeSession>(entry.Value, JsonOpts);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "AuthCodeStore: failed to deserialise entry for code {Code}", code);
            return null;
        }

        if (session is null) return null;
        if (session.UsedAt.HasValue)
        {
            // Already consumed — the dedicated "reuse" path in AuthService
            // is responsible for revoking refresh tokens; we just signal it.
            return session;
        }

        // CAS the "used" flag in. If another caller raced us and consumed
        // the code first, the revision will mismatch and UpdateAsync throws.
        var usedSession = session with { UsedAt = DateTimeOffset.UtcNow };
        var updatedBytes = JsonSerializer.SerializeToUtf8Bytes(usedSession, JsonOpts);
        try
        {
            await kv.UpdateAsync(code, updatedBytes, entry.Revision, cancellationToken: ct);
        }
        catch (NatsKVWrongLastRevisionException)
        {
            _logger.LogWarning("AuthCodeStore: concurrent use detected for code {Code}", code);
            // Whoever else got there first will get the success path; we
            // surface as a "reuse" by returning the session with UsedAt set
            // so the caller's reuse-detection logic fires.
            return session with { UsedAt = DateTimeOffset.UtcNow };
        }

        return session;
    }

    public async Task DeleteAsync(string code, CancellationToken ct = default)
    {
        var kv = await GetStoreAsync(ct);
        try
        {
            await kv.DeleteAsync(code, cancellationToken: ct);
        }
        catch (NatsKVKeyNotFoundException) { /* fine */ }
    }
}

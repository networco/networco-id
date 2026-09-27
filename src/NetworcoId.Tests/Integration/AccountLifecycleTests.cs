using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NetworcoId.Core.Security;
using NetworcoId.Endpoints;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;
using NetworcoId.Services;
using Xunit;

namespace NetworcoId.Tests.Integration;

/// <summary>
/// Deactivation must actually keep a user out (it used to be checked only on refresh),
/// and the server-to-server API networco-app uses for account deletion must be locked
/// to the shared service key. Reuses the lockout host: in-memory DB, no NATS, no email.
/// </summary>
public class AccountLifecycleTests : IClassFixture<LoginLockoutFactory>
{
    private const string Password = "CorrectHorse@1234";
    private const string ServiceKey = "test-service-key";

    private readonly LoginLockoutFactory _factory;
    public AccountLifecycleTests(LoginLockoutFactory factory) => _factory = factory;

    private NetworcoIdConfig Config => _factory.Services.GetRequiredService<NetworcoIdConfig>();

    private async Task<(Guid Id, string Email)> CreateUserAsync()
    {
        var id = Guid.NewGuid();
        var email = $"lifecycle-{id:N}@example.com";
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

        db.Users.Add(new UserEntity { Id = id, Email = email, FirstName = "Slett", LastName = "Meg", IsActive = true, EmailVerified = true });
        db.UserCredentials.Add(new UserCredentialEntity { Id = id, PasswordHash = hasher.HashPassword(Password), CreatedAt = DateTimeOffset.UtcNow });
        db.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = Guid.NewGuid(), UserId = id, TokenHash = $"hash-{id:N}",
            CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddDays(7)
        });
        await db.SaveChangesAsync();
        return (id, email);
    }

    private async Task<T> WithScopeAsync<T>(Func<IServiceProvider, Task<T>> action)
    {
        using var scope = _factory.Services.CreateScope();
        return await action(scope.ServiceProvider);
    }

    [Fact]
    public async Task Deactivated_user_cannot_log_in_or_refresh_but_wrong_password_reveals_nothing()
    {
        var (id, email) = await CreateUserAsync();

        await WithScopeAsync(sp => sp.GetRequiredService<IAccountLifecycleService>().DeactivateAsync(id, "test"));

        var result = await WithScopeAsync(sp => sp.GetRequiredService<IAuthService>().AuthenticateAsync(email, Password));
        Assert.Equal(AuthenticationOutcome.Disabled, result.Outcome);
        Assert.Null(result.User);

        var wrong = await WithScopeAsync(sp => sp.GetRequiredService<IAuthService>().AuthenticateAsync(email, "Wrong@12345678"));
        Assert.Equal(AuthenticationOutcome.InvalidCredentials, wrong.Outcome);

        var viaRefresh = await WithScopeAsync(sp => sp.GetRequiredService<IAuthService>().GetUserByRefreshTokenAsync($"hash-{id:N}"));
        Assert.Null(viaRefresh);

        var token = await WithScopeAsync(sp => sp.GetRequiredService<AuthDbContext>().RefreshTokens.AsNoTracking().SingleAsync(t => t.UserId == id));
        Assert.NotNull(token.RevokedAt);
    }

    [Fact]
    public async Task Reactivated_user_can_log_in_again()
    {
        var (id, email) = await CreateUserAsync();
        await WithScopeAsync(sp => sp.GetRequiredService<IAccountLifecycleService>().DeactivateAsync(id, "test"));
        await WithScopeAsync(sp => sp.GetRequiredService<IAccountLifecycleService>().ReactivateAsync(id, "test"));

        var result = await WithScopeAsync(sp => sp.GetRequiredService<IAuthService>().AuthenticateAsync(email, Password));
        Assert.Equal(AuthenticationOutcome.Success, result.Outcome);
    }

    [Fact]
    public async Task Delete_removes_the_user_and_scrubs_their_email_from_the_audit_log()
    {
        var (id, email) = await CreateUserAsync();
        // A failed login for the email alone is logged without a user id.
        await WithScopeAsync(sp => sp.GetRequiredService<IAuthService>().AuthenticateAsync(email, "Wrong@12345678"));
        // …and a row that names the email in another case, with no user id at all.
        await WithScopeAsync(async sp =>
        {
            var db = sp.GetRequiredService<AuthDbContext>();
            db.AuditLogs.Add(new AuditLogEntity { Id = Guid.NewGuid(), EventType = "LoginFailed", Description = $"Login attempt for unknown user: {email.ToUpperInvariant()}", Timestamp = DateTimeOffset.UtcNow });
            return await db.SaveChangesAsync();
        });

        Assert.True(await WithScopeAsync(sp => sp.GetRequiredService<IAccountLifecycleService>().DeleteAsync(id, "test")));

        var db = _factory.Services.CreateScope().ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.False(await db.Users.AnyAsync(u => u.Id == id));
        Assert.False(await db.RefreshTokens.AnyAsync(t => t.UserId == id));
        var leaks = await db.AuditLogs.AsNoTracking().ToListAsync();
        Assert.DoesNotContain(leaks, l => l.Description.Contains(email, StringComparison.OrdinalIgnoreCase));

        // Already gone → false, so callers can treat a retry as done.
        Assert.False(await WithScopeAsync(sp => sp.GetRequiredService<IAccountLifecycleService>().DeleteAsync(id, "test")));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("wrong-key")]
    public async Task Service_api_rejects_missing_or_wrong_key(string? key)
    {
        Config.ServiceApiKey = ServiceKey;
        var (id, _) = await CreateUserAsync();
        var client = _factory.CreateClient();
        if (key != null) client.DefaultRequestHeaders.Add(ServiceEndpoints.ServiceKeyHeader, key);

        var response = await client.PostAsJsonAsync($"/api/service/users/{id}/deactivate", new { reason = "test" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Service_api_is_closed_when_no_key_is_configured()
    {
        Config.ServiceApiKey = null;
        var (id, _) = await CreateUserAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add(ServiceEndpoints.ServiceKeyHeader, "");

        var response = await client.PostAsJsonAsync($"/api/service/users/{id}/deactivate", new { reason = "test" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Service_api_deactivates_and_deletes_with_the_right_key()
    {
        Config.ServiceApiKey = ServiceKey;
        var (id, _) = await CreateUserAsync();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add(ServiceEndpoints.ServiceKeyHeader, ServiceKey);

        var deactivate = await client.PostAsJsonAsync($"/api/service/users/{id}/deactivate", new { reason = "deletion requested" });
        Assert.Equal(HttpStatusCode.NoContent, deactivate.StatusCode);
        var isActive = await WithScopeAsync(sp => sp.GetRequiredService<AuthDbContext>().Users.AsNoTracking().Where(u => u.Id == id).Select(u => u.IsActive).SingleAsync());
        Assert.False(isActive);

        var unknown = await client.PostAsJsonAsync($"/api/service/users/{Guid.NewGuid()}/deactivate", new { reason = "x" });
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/service/users/{id}")).StatusCode);
        // Idempotent.
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/service/users/{id}")).StatusCode);
    }

    [Fact]
    public async Task Delete_scrubs_rows_naming_the_national_id_but_leaves_other_users_similar_emails_alone()
    {
        var (id, email) = await CreateUserAsync();
        const string nationalId = "01020312345";
        var otherEmail = "k" + email; // contains the deleted email as a substring
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var user = await db.Users.SingleAsync(u => u.Id == id);
            user.NationalId = nationalId;
            db.AuditLogs.AddRange(
                new AuditLogEntity { Id = Guid.NewGuid(), EventType = "LoginFailed", Description = $"Login attempt for unknown user: {nationalId}", Timestamp = DateTimeOffset.UtcNow },
                new AuditLogEntity { Id = Guid.NewGuid(), EventType = "LoginFailed", Description = $"Login attempt for unknown user: {otherEmail}", IpAddress = "10.0.0.1", Timestamp = DateTimeOffset.UtcNow });
            await db.SaveChangesAsync();
        }

        Assert.True(await WithScopeAsync(sp => sp.GetRequiredService<IAccountLifecycleService>().DeleteAsync(id, "test")));

        var logs = await WithScopeAsync(sp => sp.GetRequiredService<AuthDbContext>().AuditLogs.AsNoTracking().ToListAsync());
        Assert.DoesNotContain(logs, l => l.Description.Contains(nationalId));
        var other = Assert.Single(logs, l => l.Description.EndsWith(otherEmail));
        Assert.Equal("10.0.0.1", other.IpAddress);
    }

    [Theory]
    [InlineData("Login attempt for unknown user: ola@x.no", "ola@x.no", true)]
    [InlineData("User logged in: OLA@X.NO.", "ola@x.no", true)]
    [InlineData("Login attempt for unknown user: kola@x.no", "ola@x.no", false)]
    [InlineData("Login attempt for unknown user: ola@x.no.uk", "ola@x.no", false)]
    [InlineData("Login attempt for unknown user: 01020312345", "01020312345", true)]
    [InlineData("Login attempt for unknown user: 101020312345", "01020312345", false)]
    public void MentionsIdentifier_matches_whole_tokens_only(string text, string identifier, bool expected) =>
        Assert.Equal(expected, AccountLifecycleService.MentionsIdentifier(text, identifier));
}

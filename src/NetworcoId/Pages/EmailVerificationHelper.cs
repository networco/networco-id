using System.Security.Cryptography;
using System.Web;
using Microsoft.AspNetCore.Http;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services.Messaging;

namespace NetworcoId.Pages;

/// <summary>
/// Shared logic for issuing or re-issuing an email-verification link.
/// Keeps the registration, login (resend), and verify (resend) flows in sync
/// so the same expiry, cookie binding, URL shape and email body apply everywhere.
/// </summary>
public static class EmailVerificationHelper
{
    /// <summary>How long a freshly-issued verification link stays valid.</summary>
    public static readonly TimeSpan TokenLifetime = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Generates a fresh verification token + same-browser binding id, persists
    /// them on the user row, sets the binding cookie on the current response,
    /// and queues the verification email. Replaces any existing pending token.
    /// </summary>
    public static async Task SendAsync(
        HttpContext httpContext,
        AuthDbContext dbContext,
        IEmailService emailService,
        UserEntity user,
        string baseUrl,
        string returnUrl)
    {
        var verificationToken = UrlSafeRandomToken();
        var verifySessionId = UrlSafeRandomToken();

        user.EmailVerificationToken = verificationToken;
        user.EmailVerificationTokenExpiresAt = DateTimeOffset.UtcNow.Add(TokenLifetime);
        user.EmailVerificationSessionId = verifySessionId;
        await dbContext.SaveChangesAsync();

        httpContext.Response.Cookies.Append(
            RegisterModel.VerifyCookieName,
            verifySessionId,
            new CookieOptions
            {
                HttpOnly = true,
                // Allow plain HTTP only on localhost; require Secure (HTTPS) in any
                // real environment so the cookie can't leak over the wire.
                Secure = !httpContext.Request.Host.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase),
                SameSite = SameSiteMode.Lax,
                Path = "/",
                Expires = DateTimeOffset.UtcNow.Add(TokenLifetime).AddMinutes(5),
            });

        var verifyUrl = $"{baseUrl.TrimEnd('/')}/verify?token={verificationToken}&return_url={HttpUtility.UrlEncode(returnUrl ?? string.Empty)}";

        await emailService.SendEmailAsync(
            user.Email,
            "Bekreft NETWORCO-kontoen din",
            $"Takk for at du registrerte deg på NETWORCO! Bekreft e-postadressen din for å fullføre registreringen. {verifyUrl}",
            user.FirstName);
    }

    private static string UrlSafeRandomToken()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
}

using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using Microsoft.EntityFrameworkCore;
using NATS.Client.Core;
using NetworcoId.Core.Models;
using NetworcoId.Models.Auth;
using Microsoft.Extensions.Options;

using NetworcoId.Services.Messaging;

namespace NetworcoId.Pages;

public class RegisterModel(
    AuthDbContext dbContext,
    IEmailService emailService,
    IPasswordHasher passwordHasher,
    IPasswordValidator passwordValidator,
    IOptions<NetworcoIdConfig> config,
    ILogger<RegisterModel> logger) : PageModel
{
    private readonly NetworcoIdConfig _config = config.Value;
    public int MinPasswordLength => _config.MinPasswordLength;
    // Password policy flags surfaced to the view so the requirement checklist and
    // client-side validation mirror the server policy exactly (see PasswordValidator).
    // Previously the view hardcoded upper/lower/digit and silently omitted the
    // special-character rule, so users were rejected for a requirement never shown.
    public bool RequireDigit => _config.RequireDigit;
    public bool RequireUppercase => _config.RequireUppercase;
    public bool RequireLowercase => _config.RequireLowercase;
    public bool RequireNonAlphanumeric => _config.RequireNonAlphanumeric;
    public string? ErrorMessage { get; set; }
    public string ReturnUrl { get; set; } = string.Empty;
    public bool RegistrationSuccess { get; set; }

    /// <summary>Whether external BankID registration (via IDura) is configured/enabled.</summary>
    public bool IduraEnabled => _config.IduraEnabled;

    /// <summary>
    /// Link target for the BankID button — mirrors the Login page. The OAuth
    /// request is packed into <see cref="ReturnUrl"/> (a "/Login?..." URL built
    /// when registration is bounced here), so we unpack those params and rebuild
    /// the /oauth/authorize flow that resumes after BankID completes.
    /// </summary>
    public string BankIdChallengeUrl
    {
        get
        {
            var q = ParseReturnUrlQuery(ReturnUrl);
            return BankIdChallenge.BuildUrl(
                q["client_id"], q["redirect_uri"], q["scope"], q["state"],
                q["code_challenge"], q["code_challenge_method"], q["nonce"]);
        }
    }

    private static System.Collections.Specialized.NameValueCollection ParseReturnUrlQuery(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) return new System.Collections.Specialized.NameValueCollection();
        var qIndex = returnUrl.IndexOf('?');
        return qIndex >= 0
            ? HttpUtility.ParseQueryString(returnUrl[(qIndex + 1)..])
            : new System.Collections.Specialized.NameValueCollection();
    }

    /// <summary>Cookie name for the same-browser verification binding (see Verify).</summary>
    public const string VerifyCookieName = "nwid_verify_session";

    private string SanitizeReturnUrl(string? url) =>
        string.IsNullOrWhiteSpace(url) ? _config.FrontendUrl : url;

    public void OnGet(string? return_url)
    {
        ReturnUrl = SanitizeReturnUrl(return_url);
    }

    public async Task<IActionResult> OnPostAsync(
        string firstName,
        string lastName,
        string email,
        string password,
        string confirmPassword,
        string? return_url)
    {
        email = email?.Trim() ?? string.Empty;

        if (string.IsNullOrEmpty(firstName) || string.IsNullOrEmpty(lastName) || 
            string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
        {
            logger.LogWarning("Registration failed - Missing required fields: {F} {L} {E} {P}", 
                string.IsNullOrEmpty(firstName), string.IsNullOrEmpty(lastName), 
                string.IsNullOrEmpty(email), string.IsNullOrEmpty(password));
            ErrorMessage = "Alle felt er påkrevd";
            ReturnUrl = SanitizeReturnUrl(return_url);
            return Page();
        }

        if (password != confirmPassword)
        {
            ErrorMessage = "Passordene er ikke like";
            ReturnUrl = SanitizeReturnUrl(return_url);
            return Page();
        }

        var validationResult = passwordValidator.Validate(
            password,
            _config.MinPasswordLength,
            _config.RequireDigit,
            _config.RequireUppercase,
            _config.RequireLowercase,
            _config.RequireNonAlphanumeric);
        if (!validationResult.IsValid)
        {
            ErrorMessage = validationResult.ErrorMessage;
            ReturnUrl = SanitizeReturnUrl(return_url);
            return Page();
        }

        ReturnUrl = SanitizeReturnUrl(return_url);

        try
        {
            logger.LogInformation("Processing registration for {Email}", email);
            // Check if user already exists
            var existingUser = await dbContext.Users
                .FirstOrDefaultAsync(u => u.Email == email);

            if (existingUser != null)
            {
                ErrorMessage = "E-post er allerede registrert";
                return Page();
            }

            // Create user (token + session id will be set by the helper).
            var user = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = email,
                FirstName = firstName,
                LastName = lastName,
                EmailVerified = false,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };

            // Create credentials
            var credential = new UserCredentialEntity
            {
                Id = user.Id,
                PasswordHash = passwordHasher.HashPassword(password),
                CreatedAt = DateTimeOffset.UtcNow
            };

            dbContext.Users.Add(user);
            dbContext.UserCredentials.Add(credential);
            await dbContext.SaveChangesAsync();

            // Generate the verification token + same-browser binding cookie and
            // queue the email. Centralised in EmailVerificationHelper so the
            // resend flows on Login + Verify use exactly the same shape.
            await EmailVerificationHelper.SendAsync(
                HttpContext, dbContext, emailService, user, _config.BaseUrl, ReturnUrl);

            logger.LogInformation("User {Email} registered, verification email queued", email);

            // Show success message
            RegistrationSuccess = true;
            return Page();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during registration");
            ErrorMessage = "Registration failed. Please try again.";
            return Page();
        }
    }
}

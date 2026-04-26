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
    public string? ErrorMessage { get; set; }
    public string ReturnUrl { get; set; } = string.Empty;
    public bool RegistrationSuccess { get; set; }

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

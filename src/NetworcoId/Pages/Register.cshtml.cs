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

namespace NetworcoId.Pages;

public class RegisterModel(
    AuthDbContext dbContext,
    INatsConnection nats,
    IPasswordHasher passwordHasher,
    IPasswordValidator passwordValidator,
    ILogger<RegisterModel> logger) : PageModel
{
    public string? ErrorMessage { get; set; }
    public string ReturnUrl { get; set; } = string.Empty;
    public bool RegistrationSuccess { get; set; }

    public void OnGet(string? return_url)
    {
        ReturnUrl = return_url ?? "http://localhost:3000";
    }

    public async Task<IActionResult> OnPostAsync(
        string firstName,
        string lastName,
        string email,
        string password,
        string confirmPassword,
        string? return_url)
    {
        logger.LogInformation("Registration attempt - FirstName: {FirstName}, LastName: {LastName}, Email: {Email}, ReturnUrl: {ReturnUrl}", 
            firstName, lastName, email, return_url);

        if (string.IsNullOrEmpty(firstName) || string.IsNullOrEmpty(lastName) || 
            string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
        {
            logger.LogWarning("Registration failed - Missing required fields");
            ErrorMessage = "Alle felt er påkrevd";
            ReturnUrl = return_url ?? "http://localhost:3000";
            return Page();
        }

        if (password != confirmPassword)
        {
            ErrorMessage = "Passordene er ikke like";
            ReturnUrl = return_url ?? "http://localhost:3000";
            return Page();
        }

        var validationResult = passwordValidator.Validate(password);
        if (!validationResult.IsValid)
        {
            ErrorMessage = validationResult.ErrorMessage;
            ReturnUrl = return_url ?? "http://localhost:3000";
            return Page();
        }

        ReturnUrl = return_url ?? "http://localhost:3000";

        try
        {
            // Check if user already exists
            var existingUser = await dbContext.Users
                .FirstOrDefaultAsync(u => u.Email == email);

            if (existingUser != null)
            {
                ErrorMessage = "E-post er allerede registrert";
                return Page();
            }

            // Generate verification token
            var verificationToken = Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

            // Create user
            var user = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = email,
                FirstName = firstName,
                LastName = lastName,
                EmailVerificationToken = verificationToken,
                EmailVerificationTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
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

            // Send NATS message to worker to send verification email
            var emailMessage = new EmailVerificationMessage(email, verificationToken, firstName);

            await nats.PublishAsync(NetworcoIdSubjects.EmailVerify, emailMessage);
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

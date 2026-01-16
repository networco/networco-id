using System.Text;
using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;

using NetworcoId.Services.Audit;
using NetworcoId.Services.Messaging;
using NATS.Client.Core;
using NetworcoId.Core.Models;
using NetworcoId.Core;

namespace NetworcoId.Services;

/// <summary>
/// Authentication service.
/// Handles user authentication, token management, and OAuth2 flows.
/// </summary>
public interface IAuthService
{
    Task<NetworcoIdUserDto?> AuthenticateUserAsync(string emailOrNationalId, string password);
    Task<NetworcoIdUserDto?> GetUserByEmailOrNationalIdAsync(string emailOrNationalId);
    Task<NetworcoIdUserDto?> ValidateAuthorizationCodeAsync(string code, string redirectUri, string? clientId = null, bool isRegistration = false);
    Task<NetworcoIdUserDto?> RegisterUserAsync(string email, string password, string firstName, string lastName, string? nationalId, string? phoneNumber);
    string CreateAuthorizationCode(string emailOrNationalId, string redirectUri, string? state, string? clientId = null);
    Task StoreRefreshTokenAsync(Guid userId, string tokenHash, DateTimeOffset expiresAt);
    Task<NetworcoIdUserDto?> GetUserByRefreshTokenAsync(string tokenHash);
    Task<bool> ValidateRefreshTokenAsync(string tokenHash);
    Task RevokeRefreshTokenAsync(string tokenHash);
    Task RotateRefreshTokenAsync(string oldTokenHash, string newTokenHash, DateTimeOffset expiresAt);
    Task<bool> ChangePasswordAsync(string emailOrNationalId, string currentPassword, string newPassword);
    
    // Password Reset
    Task<bool> InitiatePasswordResetAsync(string email);
    Task<bool> ResetPasswordWithTokenAsync(string token, string newPassword);
}

/// <summary>
/// Authentication service implementation.
/// </summary>
public class AuthService : IAuthService
{
    private readonly AuthDbContext _context;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ILogger<AuthService> _logger;
    private readonly NetworcoIdConfig _config;
    private readonly IAuditService _auditService;
    private readonly IEmailService _emailService;
    private readonly INatsConnection _nats;
    private readonly IPasswordValidator _passwordValidator;

    // In-memory storage for auth codes (stateless, short-lived)
    private static readonly ConcurrentDictionary<string, AuthCodeSession> _authCodes = new();
    private static readonly TimeSpan CodeExpiration = TimeSpan.FromMinutes(5);

    public AuthService(
        AuthDbContext context,
        IPasswordHasher passwordHasher,
        ILogger<AuthService> logger,
        NetworcoIdConfig config,
        IAuditService auditService,
        IEmailService emailService,
        INatsConnection nats,
        IPasswordValidator passwordValidator)
    {
        _context = context;
        _passwordHasher = passwordHasher;
        _logger = logger;
        _config = config;
        _auditService = auditService;
        _emailService = emailService;
        _nats = nats;
        _passwordValidator = passwordValidator;
    }

    public async Task<NetworcoIdUserDto?> AuthenticateUserAsync(string emailOrNationalId, string password)
    {
        if (string.IsNullOrWhiteSpace(emailOrNationalId) || string.IsNullOrEmpty(password))
        {
            return null;
        }

        var identifier = emailOrNationalId.Trim();

        // Find user by email or national ID, with credentials
        var user = await _context.Users
            .AsNoTracking()
            .Include(u => u.Credential)
            .Where(u =>
                (u.Email != null && u.Email.ToLower() == identifier.ToLower()) ||
                (u.NationalId != null && u.NationalId == identifier) ||
                (u.PhoneNumber != null && u.PhoneNumber == identifier))
            .FirstOrDefaultAsync();

        if (user is null || user.Credential is null)
        {
            _logger.LogWarning("NETWORCO ID login attempt for unknown identifier {Identifier}", identifier);
            await _auditService.LogAsync("LoginFailed", $"Login attempt for unknown user: {identifier}");
            return null;
        }

        // Check if account is locked
        if (user.Credential.LockedUntil.HasValue && user.Credential.LockedUntil.Value > DateTimeOffset.UtcNow)
        {
            _logger.LogWarning("Login attempt for locked account: {Identifier}", identifier);
            await _auditService.LogAsync("LoginFailed", $"Login attempt for locked account: {user.Email}", user.Id);
            return null;
        }

        if (!_passwordHasher.VerifyPassword(password, user.Credential.PasswordHash))
        {
            _logger.LogWarning("Invalid password for identifier {Identifier}", identifier);
            
            // Increment failed attempts and check for lockout
            var cred = await _context.UserCredentials.FindAsync(user.Id);
            if (cred != null)
            {
                cred.FailedLoginAttempts++;
                cred.LastFailedLoginAt = DateTimeOffset.UtcNow;
                
                if (cred.FailedLoginAttempts >= _config.MaxFailedLoginAttempts)
                {
                    cred.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(_config.LockoutDurationMinutes);
                    _logger.LogWarning("User account locked: {Email} for {Minutes} minutes", user.Email, _config.LockoutDurationMinutes);
                    
                    await _emailService.SendEmailAsync(
                        user.Email, 
                        "NETWORCO ID: Account Locked", 
                        $"Your account has been temporarily locked due to too many failed login attempts. It will be automatically unlocked in {_config.LockoutDurationMinutes} minutes.",
                        user.FirstName);
                }
                
                _context.UserCredentials.Update(cred);
                await _context.SaveChangesAsync();
            }

            await _auditService.LogAsync("LoginFailed", $"Invalid password for user: {user.Email}", user.Id);
            return null;
        }

        await _auditService.LogAsync("LoginSuccess", $"User logged in: {user.Email}", user.Id);

        // Reset failed attempts on success
        if (user.Credential.FailedLoginAttempts > 0)
        {
            var cred = await _context.UserCredentials.FindAsync(user.Id);
            if (cred != null)
            {
                cred.FailedLoginAttempts = 0;
                cred.LastFailedLoginAt = null;
                cred.LockedUntil = null;
                _context.UserCredentials.Update(cred);
                await _context.SaveChangesAsync();
            }
        }

        return new NetworcoIdUserDto
        {
            Id = user.Id,
            NationalId = user.NationalId ?? user.PhoneNumber ?? user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            // Removed: Role - authorization handled by resource server
            Password = null,
            MustChangePassword = user.Credential.MustChangePassword
        };
    }

    public async Task<NetworcoIdUserDto?> RegisterUserAsync(string email, string password, string firstName, string lastName, string? nationalId, string? phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password) ||
            string.IsNullOrWhiteSpace(firstName) || string.IsNullOrWhiteSpace(lastName))
        {
            throw new ArgumentException("Email, password, first name, and last name are required");
        }

        // Check if user already exists
        var existingUser = await _context.Users
            .AsNoTracking()
            .Where(u => u.Email == email ||
                       (nationalId != null && u.NationalId == nationalId) ||
                       (phoneNumber != null && u.PhoneNumber == phoneNumber))
            .FirstOrDefaultAsync();

        if (existingUser != null)
        {
            throw new InvalidOperationException("User with this email, national ID, or phone number already exists");
        }

        var validationResult = _passwordValidator.Validate(password);
        if (!validationResult.IsValid)
        {
            throw new ArgumentException(validationResult.ErrorMessage);
        }

        // Create new user
        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            Email = email,
            FirstName = firstName,
            LastName = lastName,
            NationalId = nationalId,
            PhoneNumber = phoneNumber,
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Create user credentials
        var hashedPassword = _passwordHasher.HashPassword(password);
        var credential = new UserCredentialEntity
        {
            Id = user.Id, // Same ID as user (1:1 relationship)
            PasswordHash = hashedPassword,
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Save to database
        _context.Users.Add(user);
        _context.UserCredentials.Add(credential);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Created new user account for {Email}", email);

        await _auditService.LogAsync("AccountCreated", $"New account created: {email}", user.Id);

        // Notify user about registration
        await _emailService.SendEmailAsync(
            email,
            "Welcome to NETWORCO ID",
            $"Your account has been successfully created. Welcome aboard, {firstName}!",
            firstName);

        return new NetworcoIdUserDto
        {
            Id = user.Id,
            NationalId = user.NationalId ?? user.PhoneNumber ?? user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            // Removed: Role - authorization handled by resource server
            Password = null
        };
    }

    public async Task<NetworcoIdUserDto?> GetUserByEmailOrNationalIdAsync(string emailOrNationalId)
    {
        if (string.IsNullOrWhiteSpace(emailOrNationalId))
        {
            return null;
        }

        var identifier = emailOrNationalId.Trim();

        var user = await _context.Users
            .AsNoTracking()
            .Where(u =>
                (u.Email != null && u.Email.ToLower() == identifier.ToLower()) ||
                (u.NationalId != null && u.NationalId == identifier) ||
                (u.PhoneNumber != null && u.PhoneNumber == identifier))
            .FirstOrDefaultAsync();

        if (user == null)
            return null;

        return new NetworcoIdUserDto
        {
            Id = user.Id,
            NationalId = user.NationalId ?? user.PhoneNumber ?? user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            // Removed: Role - authorization handled by resource server
            Password = null
        };
    }

    public string CreateAuthorizationCode(string emailOrNationalId, string redirectUri, string? state, string? clientId = null)
    {
        // Stateless code: email|redirectUri|clientId|timestamp
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var plainText = $"{emailOrNationalId}|{redirectUri}|{clientId ?? ""}|{timestamp}";
        var bytes = Encoding.UTF8.GetBytes(plainText);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }

    public async Task<NetworcoIdUserDto?> ValidateAuthorizationCodeAsync(string code, string redirectUri, string? clientId = null, bool isRegistration = false)
    {
        try
        {
            // Handle NETWORCO ID authorization codes
            if (code.StartsWith("dev_"))
            {
                var isRegistrationCode = code.Contains("_reg");
                if (isRegistrationCode)
                {
                    // For registration, create a new user with NETWORCO ID data
                    var simulatedUser = await CreateSimulatedUserForRegistrationAsync();
                    return simulatedUser;
                }
                else
                {
                    // For login, this would normally validate against existing users
                    // For now, return null to indicate no existing user found
                    return null;
                }
            }

            // Handle legacy authorization codes (for backward compatibility)
            // Decode the code
            var paddedCode = code.Replace("-", "+").Replace("_", "/");
            while (paddedCode.Length % 4 != 0) paddedCode += "=";

            var bytes = Convert.FromBase64String(paddedCode);
            var plainText = Encoding.UTF8.GetString(bytes);
            var parts = plainText.Split('|');

            if (parts.Length < 3)
                return null;

            var emailOrNationalId = parts[0];
            var originalRedirectUri = parts[1];
            
            string? originalClientId = null;
            long timestamp;

            if (parts.Length == 4)
            {
                originalClientId = parts[2];
                timestamp = long.Parse(parts[3]);
            }
            else
            {
                // Legacy format
                timestamp = long.Parse(parts[2]);
            }

            // Verify redirect URI matches (case-insensitive for local development)
            var normalizedOriginal = originalRedirectUri.TrimEnd('/');
            var normalizedActual = redirectUri.TrimEnd('/');

            if (!string.Equals(normalizedOriginal, normalizedActual, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Authorization code validation failed: redirect_uri mismatch. Expected {Expected}, Got {Actual}", originalRedirectUri, redirectUri);
                return null;
            }

            // Verify client ID matches (if provided)
            if (clientId != null && originalClientId != null && originalClientId != clientId)
            {
                // Allow trusted API clients to exchange codes for other clients (BFF pattern)
                // This is required because the Web app initiates the flow, but the API service
                // performs the final token exchange.
                var exchangingClient = await _context.OAuthClients
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.ClientId == clientId);

                if (exchangingClient == null || !exchangingClient.IsTrustedForExchange)
                {
                    _logger.LogWarning("Authorization code validation failed: client_id mismatch and client {Actual} is not trusted for exchange. Expected {Expected}", clientId, originalClientId);
                    return null;
                }
                
                _logger.LogInformation("Trusted API client {ApiClient} is exchanging code for client {OriginalClient}", clientId, originalClientId);
            }

            // Check expiration
            var codeAge = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp;
            if (codeAge > CodeExpiration.TotalSeconds)
                return null;

            // Get user from database
            var user = await GetUserByEmailOrNationalIdAsync(emailOrNationalId);
            return user;
        }
        catch
        {
            return null;
        }
    }

    private async Task<NetworcoIdUserDto?> CreateSimulatedUserForRegistrationAsync()
    {
        // Generate NETWORCO ID user data
        var firstNames = new[] { "Emma", "Oliver", "Sofia", "Lucas", "Ingrid", "Mathias", "Thea", "Emil" };
        var lastNames = new[] { "Hansen", "Johansen", "Olsen", "Larsen", "Andersen", "Pedersen", "Nielsen", "Kristiansen" };

        var random = new Random();
        var firstName = firstNames[random.Next(firstNames.Length)];
        var lastName = lastNames[random.Next(lastNames.Length)];
        var nationalId = $"0{random.Next(100000, 999999)}{random.Next(10000, 99999)}"; // Fake fødselsnummer
        var email = $"{firstName.ToLower()}.{lastName.ToLower()}@example.com";
        var phoneNumber = $"+47{random.Next(90000000, 99999999)}";

        try
        {
            // Create the user in database
            var user = await RegisterUserAsync(
                email,
                "TempPassword123!", // Temporary password - user should change this
                firstName,
                lastName,
                nationalId,
                phoneNumber);

            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create NETWORCO ID user for registration");
            return null;
        }
    }

    public async Task StoreRefreshTokenAsync(Guid userId, string tokenHash, DateTimeOffset expiresAt)
    {
        var refreshToken = new RefreshTokenEntity
        {
            UserId = userId,
            TokenHash = tokenHash,
            ExpiresAt = expiresAt,
            CreatedAt = DateTimeOffset.UtcNow
        };

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
    }

    public async Task<bool> ValidateRefreshTokenAsync(string tokenHash)
    {
        var token = await _context.RefreshTokens
            .AsNoTracking()
            .Where(t => t.TokenHash == tokenHash)
            .FirstOrDefaultAsync();

        if (token == null)
            return false;

        // If revoked, check if it was revoked recently (grace period for rotation)
        if (token.RevokedAt != null)
        {
            // Allow 60 second grace period for token rotation to handle concurrent requests
            return token.RevokedAt > DateTimeOffset.UtcNow.AddSeconds(-60) && 
                   token.ExpiresAt > DateTimeOffset.UtcNow;
        }

        return token.ExpiresAt > DateTimeOffset.UtcNow;
    }

    public async Task<NetworcoIdUserDto?> GetUserByRefreshTokenAsync(string tokenHash)
    {
        var token = await _context.RefreshTokens
            .AsNoTracking()
            .Include(t => t.User)
            .Where(t => t.TokenHash == tokenHash)
            .FirstOrDefaultAsync();

        if (token == null)
            return null;

        // Check expiration and revocation (with grace period)
        var isValid = token.RevokedAt == null 
            ? token.ExpiresAt > DateTimeOffset.UtcNow
            : token.RevokedAt > DateTimeOffset.UtcNow.AddSeconds(-60) && token.ExpiresAt > DateTimeOffset.UtcNow;

        if (!isValid)
            return null;

        var user = token.User;
        return new NetworcoIdUserDto
        {
            Id = user.Id,
            NationalId = user.NationalId ?? user.PhoneNumber ?? user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            Password = null
        };
    }

    public async Task RevokeRefreshTokenAsync(string tokenHash)
    {
        var token = await _context.RefreshTokens
            .Where(t => t.TokenHash == tokenHash)
            .FirstOrDefaultAsync();

        if (token != null)
        {
            token.RevokedAt = DateTimeOffset.UtcNow;
            await _context.SaveChangesAsync();
        }
    }

    public async Task RotateRefreshTokenAsync(string oldTokenHash, string newTokenHash, DateTimeOffset expiresAt)
    {
        var oldToken = await _context.RefreshTokens
            .Where(t => t.TokenHash == oldTokenHash)
            .FirstOrDefaultAsync();

        if (oldToken != null)
        {
            // Revoke old token
            oldToken.RevokedAt = DateTimeOffset.UtcNow;
            oldToken.ReplacedByTokenId = newTokenHash;

            // Create new token
            var newToken = new RefreshTokenEntity
            {
                UserId = oldToken.UserId,
                TokenHash = newTokenHash,
                ExpiresAt = expiresAt,
                CreatedAt = DateTimeOffset.UtcNow
            };

            _context.RefreshTokens.Add(newToken);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<bool> ChangePasswordAsync(string emailOrNationalId, string currentPassword, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(emailOrNationalId) || string.IsNullOrEmpty(currentPassword) || string.IsNullOrEmpty(newPassword))
        {
            return false;
        }

        var identifier = emailOrNationalId.Trim();

        var user = await _context.Users
            .Include(u => u.Credential)
            .Where(u =>
                (u.Email != null && u.Email.ToLower() == identifier.ToLower()) ||
                (u.NationalId != null && u.NationalId == identifier) ||
                (u.PhoneNumber != null && u.PhoneNumber == identifier))
            .FirstOrDefaultAsync();

        if (user == null || user.Credential == null)
        {
            return false;
        }

        if (!_passwordHasher.VerifyPassword(currentPassword, user.Credential.PasswordHash))
        {
            _logger.LogWarning("ChangePassword failed for {Identifier}: Current password verification failed.", identifier);
            return false;
        }

        var validationResult = _passwordValidator.Validate(newPassword);
        if (!validationResult.IsValid)
        {
            throw new ArgumentException(validationResult.ErrorMessage);
        }

        var newHash = _passwordHasher.HashPassword(newPassword);
        _logger.LogInformation("Updating password for {Identifier}. Old hash start: {OldStart}, New hash start: {NewStart}", 
            identifier, user.Credential.PasswordHash[..10], newHash[..10]);

        user.Credential.PasswordHash = newHash;
        user.Credential.MustChangePassword = false;
        user.Credential.UpdatedAt = DateTimeOffset.UtcNow;

        _context.Users.Update(user); // Force update tracking
        await _context.SaveChangesAsync();
        
        await _auditService.LogAsync("PasswordChanged", $"User changed their password: {user.Email}", user.Id);

        // Notify user about password change
        await _emailService.SendEmailAsync(
            user.Email,
            "NETWORCO ID: Password Changed",
            "Your password was recently changed. If you did not perform this action, please contact support immediately.",
            user.FirstName);

        // Verify saved state
        var updatedUser = await _context.UserCredentials.AsNoTracking().FirstOrDefaultAsync(c => c.Id == user.Id);
        _logger.LogInformation("Password update verified for {Identifier}. Saved hash matches: {Matches}", 
            identifier, updatedUser?.PasswordHash == newHash);

        return true;
    }

    public async Task<bool> InitiatePasswordResetAsync(string email)
    {
        var user = await _context.Users
            .Where(u => u.Email != null && EF.Functions.ILike(u.Email, email))
            .FirstOrDefaultAsync();

        if (user == null)
        {
            // For security, don't reveal that the user doesn't exist
            _logger.LogWarning("Password reset requested for unknown email: {Email}", email);
            return true;
        }

        // Send reset email via the IEmailService to follow the project convention
        // This ensures the EmailWorker handles it consistently
        var token = Convert.ToBase64String(global::System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        user.PasswordResetToken = token;
        user.PasswordResetTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(2);

        _context.Users.Update(user);
        await _context.SaveChangesAsync();

        // Publish to NATS using the specialized message type for better worker handling
        await _nats.PublishAsync(NetworcoIdSubjects.PasswordReset, new PasswordResetMessage(user.Email, token, user.FirstName));

        _logger.LogInformation("Password reset initiated for {Email}", email);
        await _auditService.LogAsync("PasswordResetInitiated", $"Password reset token generated for: {email}", user.Id);

        return true;
    }

    public async Task<bool> ResetPasswordWithTokenAsync(string token, string newPassword)
    {
        var user = await _context.Users
            .Include(u => u.Credential)
            .Where(u => u.PasswordResetToken == token && u.PasswordResetTokenExpiresAt > DateTimeOffset.UtcNow)
            .FirstOrDefaultAsync();

        if (user == null || user.Credential == null)
        {
            _logger.LogWarning("Invalid or expired password reset token: {Token}", token);
            return false;
        }

        var validationResult = _passwordValidator.Validate(newPassword);
        if (!validationResult.IsValid)
        {
            throw new ArgumentException(validationResult.ErrorMessage);
        }

        var newHash = _passwordHasher.HashPassword(newPassword);
        user.Credential.PasswordHash = newHash;
        user.Credential.MustChangePassword = false;
        user.Credential.UpdatedAt = DateTimeOffset.UtcNow;
        user.Credential.FailedLoginAttempts = 0;
        user.Credential.LockedUntil = null;

        user.PasswordResetToken = null;
        user.PasswordResetTokenExpiresAt = null;

        _context.Users.Update(user);
        _context.UserCredentials.Update(user.Credential);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Password reset completed for user {Id}", user.Id);
        await _auditService.LogAsync("PasswordResetCompleted", $"Password reset completed using token for: {user.Email}", user.Id);

        // Notify user
        await _emailService.SendEmailAsync(
            user.Email,
            "NETWORCO ID: Password Reset Successful",
            "Your password has been successfully reset. You can now log in with your new password.",
            user.FirstName);

        return true;
    }

    private record AuthCodeSession(
        string EmailOrNationalId,
        string RedirectUri,
        string? State,
        DateTimeOffset CreatedAt);
}
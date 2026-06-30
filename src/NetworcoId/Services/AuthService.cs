using System.Text;
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
/// Raised by external (BankID/IDura) provisioning when the provider-supplied email is
/// unverified and already belongs to another account. We refuse to attach an unproven
/// email to someone else's account and refuse to spawn a placeholder duplicate — the
/// caller surfaces this so the user can sign in to their existing account instead.
/// </summary>
public sealed class ExternalEmailConflictException(string email)
    : Exception($"Email '{email}' is already associated with another account")
{
    public string Email { get; } = email;
}

/// <summary>Outcome of linking an external (BankID) identity to an existing account.</summary>
public enum ExternalLinkResult
{
    /// <summary>The identity was newly linked to the account.</summary>
    Linked,
    /// <summary>The identity was already linked to this account (no-op).</summary>
    AlreadyLinked,
    /// <summary>The target account could not be found.</summary>
    UserNotFound
}

/// <summary>
/// Authentication service.
/// Handles user authentication, token management, and OAuth2 flows.
/// </summary>
public interface IAuthService
{
    Task<NetworcoIdUserDto?> AuthenticateUserAsync(string emailOrNationalId, string password);
    Task<NetworcoIdUserDto?> GetUserByEmailOrNationalIdAsync(string emailOrNationalId);
    Task<(NetworcoIdUserDto? User, List<string>? Scopes, DateTimeOffset? AuthTime)> ValidateAuthorizationCodeAsync(string code, string redirectUri, string? clientId = null, string? codeVerifier = null, bool isRegistration = false);
    Task<NetworcoIdUserDto?> RegisterUserAsync(string email, string password, string firstName, string lastName, string? nationalId, string? phoneNumber);

    /// <summary>
    /// Finds the local user linked to an external provider identity, or creates/links
    /// one from the supplied claims. See the linking rules in the BankID/IDura plan.
    /// </summary>
    Task<NetworcoIdUserDto> FindOrCreateExternalUserAsync(string provider, ExternalUserInfo info);

    /// <summary>Links an external (BankID) identity to an already-authenticated account (verify-to-link).</summary>
    Task<ExternalLinkResult> LinkExternalUserAsync(Guid userId, string provider, ExternalUserInfo info);

    /// <summary>Returns all local accounts linked to an external identity (for the login account picker).</summary>
    Task<IReadOnlyList<NetworcoIdUserDto>> GetAccountsForExternalLoginAsync(string provider, string subject);

    /// <summary>Mints a one-time, short-lived ticket that authorizes connecting a BankID to <paramref name="userId"/>.</summary>
    Task<string> CreateBankIdLinkTicketAsync(Guid userId);

    /// <summary>Consumes a BankID-link ticket, returning the account id it authorizes (or null if invalid/expired).</summary>
    Task<Guid?> ConsumeBankIdLinkTicketAsync(string ticket);

    /// <summary>Revokes refresh tokens and invalidates outstanding access tokens for a user (e.g. after an email change).</summary>
    Task InvalidateActiveSessionsAsync(Guid userId);

    /// <summary>Sets (or replaces) a user's password, creating the credential row if absent.</summary>
    Task<bool> SetPasswordAsync(Guid userId, string newPassword);

    /// <summary>True when the user already has a password credential.</summary>
    Task<bool> HasPasswordAsync(Guid userId);
    Task<string> CreateAuthorizationCodeAsync(string emailOrNationalId, string redirectUri, string? state, string? clientId = null, string? codeChallenge = null, string? codeChallengeMethod = null, string? nonce = null, IEnumerable<string>? scopes = null, DateTimeOffset? authTime = null);
    Task StoreRefreshTokenAsync(Guid userId, string tokenHash, DateTimeOffset expiresAt, string? clientId = null);
    Task<NetworcoIdUserDto?> GetUserByRefreshTokenAsync(string tokenHash);
    Task<bool> ValidateRefreshTokenAsync(string tokenHash);
    Task RevokeRefreshTokenAsync(string tokenHash);
    Task RotateRefreshTokenAsync(string oldTokenHash, string newTokenHash, DateTimeOffset expiresAt);
    Task<bool> ChangePasswordAsync(string emailOrNationalId, string currentPassword, string newPassword);
    
    // Password Reset
    Task<bool> InitiatePasswordResetAsync(string email, string? returnUrl = null);
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
    private readonly IAuthCodeStore _authCodes;

    // Server-side OAuth code lifetime — must match the NATS KV bucket TTL.
    private static readonly TimeSpan CodeExpiration = TimeSpan.FromMinutes(5);

    public AuthService(
        AuthDbContext context,
        IPasswordHasher passwordHasher,
        ILogger<AuthService> logger,
        NetworcoIdConfig config,
        IAuditService auditService,
        IEmailService emailService,
        INatsConnection nats,
        IPasswordValidator passwordValidator,
        IAuthCodeStore authCodes)
    {
        _context = context;
        _passwordHasher = passwordHasher;
        _logger = logger;
        _config = config;
        _auditService = auditService;
        _emailService = emailService;
        _nats = nats;
        _passwordValidator = passwordValidator;
        _authCodes = authCodes;
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

        // Check for legacy password hash and upgrade if necessary
        if (!_passwordHasher.IsArgon2id(user.Credential.PasswordHash))
        {
            _logger.LogInformation("Upgrading password hash for user {UserId} from PBKDF2 to Argon2id", user.Id);
            
            var credToUpdate = await _context.UserCredentials.FirstOrDefaultAsync(c => c.Id == user.Id);
            if (credToUpdate != null)
            {
                credToUpdate.PasswordHash = _passwordHasher.HashPassword(password);
                credToUpdate.UpdatedAt = DateTimeOffset.UtcNow;
                
                // Also reset failed attempts if we are touching the record anyway
                credToUpdate.FailedLoginAttempts = 0;
                credToUpdate.LastFailedLoginAt = null;
                credToUpdate.LockedUntil = null;
                
                _context.UserCredentials.Update(credToUpdate);
                await _context.SaveChangesAsync();
                
                // Update the local user object's hash so we don't return stale data if used later
                user.Credential.PasswordHash = credToUpdate.PasswordHash; 
            }
        }
        else if (user.Credential.FailedLoginAttempts > 0)
        {
            // Reset failed attempts on success (only if we didn't already save above)
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
            Roles = user.Roles,
            PhoneNumber = user.PhoneNumber,
            EmailVerified = user.EmailVerified,
            PhoneNumberVerified = user.PhoneNumberVerified,
            BirthDate = user.BirthDate,
            // Removed: Role - authorization handled by resource server
            Password = null,
            MustChangePassword = user.Credential.MustChangePassword,
            
            // Map Address Fields
            AddressFormatted = user.AddressFormatted,
            AddressStreetAddress = user.AddressStreetAddress,
            AddressLocality = user.AddressLocality,
            AddressRegion = user.AddressRegion,
            AddressPostalCode = user.AddressPostalCode,
            AddressCountry = user.AddressCountry
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

        var validationResult = _passwordValidator.Validate(
            password, 
            _config.MinPasswordLength, 
            _config.RequireDigit, 
            _config.RequireUppercase, 
            _config.RequireLowercase, 
            _config.RequireNonAlphanumeric);
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
            Roles = user.Roles,
            PhoneNumber = user.PhoneNumber,
            EmailVerified = user.EmailVerified,
            PhoneNumberVerified = user.PhoneNumberVerified,
            BirthDate = user.BirthDate,
            // Removed: Role - authorization handled by resource server
            Password = null,
            
            // Map Address Fields
            AddressFormatted = user.AddressFormatted,
            AddressStreetAddress = user.AddressStreetAddress,
            AddressLocality = user.AddressLocality,
            AddressRegion = user.AddressRegion,
            AddressPostalCode = user.AddressPostalCode,
            AddressCountry = user.AddressCountry
        };
    }

    // Generated address for BankID users with no usable email; also used to detect
    // accounts that should be enriched once the provider supplies a real one.
    private const string PlaceholderEmailSuffix = "@id.networco.no";
    // Earlier placeholder domain — still recognized so pre-existing placeholder
    // accounts keep getting backfilled when a real email later arrives.
    private const string LegacyPlaceholderEmailSuffix = "@no-reply.networco.no";

    private static bool IsPlaceholderEmail(string? email) =>
        !string.IsNullOrEmpty(email)
        && email.StartsWith("bankid-", StringComparison.OrdinalIgnoreCase)
        && (email.EndsWith(PlaceholderEmailSuffix, StringComparison.OrdinalIgnoreCase)
            || email.EndsWith(LegacyPlaceholderEmailSuffix, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Synthesizes a short, deterministic placeholder email for an external identity
    /// that supplied no email. Derived from the provider reference so the same person
    /// always maps to the same address (idempotent, unique). The real reference is
    /// kept verbatim in user_external_logins.subject for identity resolution.
    /// </summary>
    private static string GeneratePlaceholderEmail(string provider, string subject)
    {
        var hash = global::System.Security.Cryptography.SHA256.HashData(
            global::System.Text.Encoding.UTF8.GetBytes($"{provider}:{subject}"));
        var token = global::System.Convert.ToHexString(hash)[..12].ToLowerInvariant(); // 48 bits, plenty
        return $"bankid-{token}{PlaceholderEmailSuffix}";
    }

    public async Task<NetworcoIdUserDto> FindOrCreateExternalUserAsync(string provider, ExternalUserInfo info)
    {
        if (string.IsNullOrWhiteSpace(info.Subject))
        {
            throw new ArgumentException("External subject is required", nameof(info));
        }

        // Email the provider supplied. BankID's address is self-asserted (the
        // editable field on the consent screen), so it's typically NOT verified —
        // we still store it, just flagged unverified.
        var providedEmail = string.IsNullOrWhiteSpace(info.Email) ? null : info.Email.Trim();
        var emailVerified = providedEmail != null && info.EmailVerified;

        // 1. Returning user: an existing link for (provider, subject).
        var link = await _context.UserExternalLogins
            .Include(l => l.User)
            .FirstOrDefaultAsync(l => l.Provider == provider && l.Subject == info.Subject);

        if (link != null)
        {
            var existing = link.User;
            // Refresh profile data the provider asserts each login.
            if (!string.IsNullOrWhiteSpace(info.FirstName)) existing.FirstName = info.FirstName;
            if (!string.IsNullOrWhiteSpace(info.LastName)) existing.LastName = info.LastName;
            if (!string.IsNullOrWhiteSpace(info.BirthDate)) existing.BirthDate = info.BirthDate;

            // Backfill a real provider-supplied email onto accounts still on the
            // generated placeholder (only if no other user holds it). Stays
            // unverified unless the provider asserts verification.
            if (providedEmail != null && IsPlaceholderEmail(existing.Email)
                && !await _context.Users.AnyAsync(u => u.Id != existing.Id && u.Email.ToLower() == providedEmail.ToLower()))
            {
                existing.Email = providedEmail;
                existing.EmailVerified = emailVerified;
            }

            link.LastLoginAt = DateTimeOffset.UtcNow;
            await _context.SaveChangesAsync();
            return MapToDto(existing);
        }

        // 2. First login for this external identity.
        // Only auto-link to an EXISTING account when the provider asserts a VERIFIED
        // email — never attach an unproven email to someone else's account.
        UserEntity? user = null;
        if (emailVerified)
        {
            user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == providedEmail!.ToLower());
        }

        if (user == null)
        {
            // New account. Decide the address for it:
            //  - a real provider email that's free  -> use it (unverified unless proven);
            //  - no provider email at all           -> a unique placeholder so login works;
            //  - a real provider email already taken -> CONFLICT. We get here only when the
            //    email is unverified (a verified match would have linked above), so we can't
            //    prove ownership and must not silently spawn a placeholder duplicate. Refuse
            //    and let the caller tell the user, so they can sign in to the existing account.
            string accountEmail;
            bool verifiedFlag;
            if (providedEmail != null)
            {
                var taken = await _context.Users.AnyAsync(u => u.Email.ToLower() == providedEmail.ToLower());
                if (taken)
                {
                    _logger.LogWarning("External login for subject {Subject}: provided email already in use — refusing to create placeholder duplicate", info.Subject);
                    throw new ExternalEmailConflictException(providedEmail);
                }
                accountEmail = providedEmail;
                verifiedFlag = emailVerified;
            }
            else
            {
                accountEmail = GeneratePlaceholderEmail(provider, info.Subject);
                verifiedFlag = false;
            }

            user = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = accountEmail,
                FirstName = info.FirstName ?? string.Empty,
                LastName = info.LastName ?? string.Empty,
                BirthDate = info.BirthDate,
                EmailVerified = verifiedFlag,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
            _context.Users.Add(user);
            await _auditService.LogAsync("AccountCreated", $"Account created via {provider}: {accountEmail}", user.Id);
        }
        else
        {
            // Linking to an existing account matched by verified email.
            if (!string.IsNullOrWhiteSpace(info.BirthDate)) user.BirthDate = info.BirthDate;
            await _auditService.LogAsync("ExternalLoginLinked", $"{provider} linked to existing account: {user.Email}", user.Id);
        }

        _context.UserExternalLogins.Add(new UserExternalLoginEntity
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Provider = provider,
            Subject = info.Subject,
            CreatedAt = DateTimeOffset.UtcNow,
            LastLoginAt = DateTimeOffset.UtcNow,
            User = user
        });

        await _context.SaveChangesAsync();
        _logger.LogInformation("Linked {Provider} identity to user {UserId}", provider, user.Id);
        return MapToDto(user);
    }

    /// <summary>
    /// Links an external (BankID) identity to an ALREADY-AUTHENTICATED account. This is the
    /// "verify-to-link" / step-up flow: the caller has proven control of <paramref name="userId"/>
    /// (an active session) and just proven the BankID, so we attach the identity to that account.
    /// A subject may be linked to several accounts (one person, multiple accounts) — login then
    /// offers an account picker. We never change the account's email here.
    /// </summary>
    public async Task<ExternalLinkResult> LinkExternalUserAsync(Guid userId, string provider, ExternalUserInfo info)
    {
        if (string.IsNullOrWhiteSpace(info.Subject))
        {
            throw new ArgumentException("External subject is required", nameof(info));
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user == null)
        {
            return ExternalLinkResult.UserNotFound;
        }

        // Idempotent: already linked to this account.
        var existing = await _context.UserExternalLogins
            .FirstOrDefaultAsync(l => l.Provider == provider && l.Subject == info.Subject && l.UserId == userId);
        if (existing != null)
        {
            existing.LastLoginAt = DateTimeOffset.UtcNow;
            // Keep the provider-asserted (BankID) name/birthdate fresh on re-verification.
            if (!string.IsNullOrWhiteSpace(info.FirstName)) existing.FirstName = info.FirstName;
            if (!string.IsNullOrWhiteSpace(info.LastName)) existing.LastName = info.LastName;
            if (!string.IsNullOrWhiteSpace(info.BirthDate)) user.BirthDate = info.BirthDate;
            await _context.SaveChangesAsync();
            _logger.LogInformation("{Provider} already linked to user {UserId} (refreshed)", provider, userId);
            return ExternalLinkResult.AlreadyLinked;
        }

        // BankID is authoritative for the birth date; fill it in if we don't have one.
        if (!string.IsNullOrWhiteSpace(info.BirthDate)) user.BirthDate = info.BirthDate;

        _context.UserExternalLogins.Add(new UserExternalLoginEntity
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Provider = provider,
            Subject = info.Subject,
            FirstName = info.FirstName,
            LastName = info.LastName,
            CreatedAt = DateTimeOffset.UtcNow,
            LastLoginAt = DateTimeOffset.UtcNow,
            User = user
        });

        await _auditService.LogAsync("ExternalLoginLinked", $"{provider} linked to existing account (step-up): {user.Email}", user.Id);
        await _context.SaveChangesAsync();
        _logger.LogInformation("Step-up linked {Provider} identity to user {UserId}", provider, user.Id);
        return ExternalLinkResult.Linked;
    }

    /// <summary>
    /// Returns every local account currently linked to the given external identity, most
    /// recently used first. Login uses this to decide: 0 → create/refuse, 1 → sign in,
    /// 2+ → show an account picker.
    /// </summary>
    public async Task<IReadOnlyList<NetworcoIdUserDto>> GetAccountsForExternalLoginAsync(string provider, string subject)
    {
        var users = await _context.UserExternalLogins
            .Where(l => l.Provider == provider && l.Subject == subject)
            .OrderByDescending(l => l.LastLoginAt)
            .Select(l => l.User)
            .ToListAsync();

        return users.Select(MapToDto).ToList();
    }

    public async Task<string> CreateBankIdLinkTicketAsync(Guid userId)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userId)
            ?? throw new InvalidOperationException($"User {userId} not found");

        var token = Convert.ToBase64String(global::System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        user.BankIdLinkToken = token;
        user.BankIdLinkTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
        await _context.SaveChangesAsync();
        return token;
    }

    public async Task<Guid?> ConsumeBankIdLinkTicketAsync(string ticket)
    {
        if (string.IsNullOrWhiteSpace(ticket)) return null;

        var user = await _context.Users.FirstOrDefaultAsync(u => u.BankIdLinkToken == ticket);
        if (user == null || user.BankIdLinkTokenExpiresAt == null || user.BankIdLinkTokenExpiresAt < DateTimeOffset.UtcNow)
        {
            return null;
        }

        // One-time use.
        user.BankIdLinkToken = null;
        user.BankIdLinkTokenExpiresAt = null;
        await _context.SaveChangesAsync();
        return user.Id;
    }

    public async Task<bool> SetPasswordAsync(Guid userId, string newPassword)
    {
        if (string.IsNullOrEmpty(newPassword)) return false;

        var user = await _context.Users
            .Include(u => u.Credential)
            .FirstOrDefaultAsync(u => u.Id == userId);
        if (user == null) return false;

        var validationResult = _passwordValidator.Validate(
            newPassword,
            _config.MinPasswordLength,
            _config.RequireDigit,
            _config.RequireUppercase,
            _config.RequireLowercase,
            _config.RequireNonAlphanumeric);
        if (!validationResult.IsValid)
        {
            throw new ArgumentException(validationResult.ErrorMessage);
        }

        var hash = _passwordHasher.HashPassword(newPassword);
        if (user.Credential == null)
        {
            _context.UserCredentials.Add(new UserCredentialEntity
            {
                Id = user.Id, // 1:1 with user
                PasswordHash = hash,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow
            });
        }
        else
        {
            user.Credential.PasswordHash = hash;
            user.Credential.MustChangePassword = false;
            user.Credential.UpdatedAt = DateTimeOffset.UtcNow;
            _context.UserCredentials.Update(user.Credential);
        }

        await _context.SaveChangesAsync();
        await _auditService.LogAsync("PasswordSet", $"User set/updated password: {user.Email}", user.Id);
        return true;
    }

    public async Task<bool> HasPasswordAsync(Guid userId)
    {
        return await _context.UserCredentials.AsNoTracking().AnyAsync(c => c.Id == userId);
    }

    /// <summary>Maps a tracked/loaded user entity to the public DTO.</summary>
    private static NetworcoIdUserDto MapToDto(UserEntity user) => new()
    {
        Id = user.Id,
        NationalId = user.NationalId ?? user.PhoneNumber ?? user.Email,
        FirstName = user.FirstName,
        LastName = user.LastName,
        Email = user.Email,
        Roles = user.Roles,
        PhoneNumber = user.PhoneNumber,
        EmailVerified = user.EmailVerified,
        PhoneNumberVerified = user.PhoneNumberVerified,
        BirthDate = user.BirthDate,
        Password = null,
        AddressFormatted = user.AddressFormatted,
        AddressStreetAddress = user.AddressStreetAddress,
        AddressLocality = user.AddressLocality,
        AddressRegion = user.AddressRegion,
        AddressPostalCode = user.AddressPostalCode,
        AddressCountry = user.AddressCountry
    };

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
            Roles = user.Roles,
            PhoneNumber = user.PhoneNumber,
            EmailVerified = user.EmailVerified,
            PhoneNumberVerified = user.PhoneNumberVerified,
            BirthDate = user.BirthDate,
            // Removed: Role - authorization handled by resource server
            Password = null,
            
            // Map Address Fields
            AddressFormatted = user.AddressFormatted,
            AddressStreetAddress = user.AddressStreetAddress,
            AddressLocality = user.AddressLocality,
            AddressRegion = user.AddressRegion,
            AddressPostalCode = user.AddressPostalCode,
            AddressCountry = user.AddressCountry
        };
    }

    public async Task<string> CreateAuthorizationCodeAsync(string emailOrNationalId, string redirectUri, string? state, string? clientId = null, string? codeChallenge = null, string? codeChallengeMethod = null, string? nonce = null, IEnumerable<string>? scopes = null, DateTimeOffset? authTime = null)
    {
        var codeId = Guid.NewGuid().ToString("N");
        var session = new AuthCodeSession(
            emailOrNationalId,
            redirectUri,
            state,
            codeChallenge,
            codeChallengeMethod,
            nonce,
            scopes?.ToList() ?? new List<string>(),
            authTime,
            DateTimeOffset.UtcNow,
            null);

        await _authCodes.PutAsync(codeId, session);
        return codeId;
    }

    public async Task<(NetworcoIdUserDto? User, List<string>? Scopes, DateTimeOffset? AuthTime)> ValidateAuthorizationCodeAsync(string code, string redirectUri, string? clientId = null, string? codeVerifier = null, bool isRegistration = false)
    {
        try
        {
            // Atomic GET + mark-as-used via NATS KV (revision CAS). The store
            // returns the session with `UsedAt = null` ONLY when we won the
            // CAS — i.e. we're the first to consume this code. Any other
            // outcome (already used at fetch time, or another caller raced
            // us) is reuse.
            var session = await _authCodes.GetAndMarkUsedAsync(code);
            if (session is not null)
            {
                if (session.UsedAt.HasValue)
                {
                    _logger.LogWarning("Security Alert: Authorization code reuse detected! Code: {Code}, User: {User}", code, session.EmailOrNationalId);
                    await RevokeAllRefreshTokensForUserAsync(session.EmailOrNationalId);
                    return (null, null, null);
                }

                // Verify expiration (defensive — KV TTL should already have
                // dropped expired entries, but check the timestamp anyway).
                if ((DateTimeOffset.UtcNow - session.CreatedAt) > CodeExpiration)
                {
                    _logger.LogWarning("Authorization code expired");
                    await _authCodes.DeleteAsync(code);
                    return (null, null, null);
                }

                // Verify Redirect URI
                var normalizedOriginal = session.RedirectUri.TrimEnd('/');
                var normalizedActual = redirectUri.TrimEnd('/');
                if (!string.Equals(normalizedOriginal, normalizedActual, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Redirect URI mismatch. Expected {Expected}, Got {Actual}", session.RedirectUri, redirectUri);
                    return (null, null, null);
                }

                if (string.IsNullOrEmpty(session.CodeChallenge))
                {
                    // OIDCC Test: If PKCE was not used in the original request, but a code_verifier IS provided now, it must be ignored or rejected.
                    // The spec says: "If the code_verifier parameter is present, it MUST be ignored if the code_challenge parameter was not present in the Authorization Request."
                    // However, strict implementations might choose to reject it to detect client confusion.
                    // For now, we will just proceed without PKCE checks if the session didn't use it.
                    // (No change needed here as we only enter this block if session.CodeChallenge IS NOT NULL)
                }
                else // PKCE was used
                {
                    if (string.IsNullOrEmpty(codeVerifier))
                    {
                        _logger.LogWarning("PKCE required but code_verifier missing");
                        return (null, null, null);
                    }

                    if (session.CodeChallengeMethod == "S256")
                    {
                        using var sha256 = global::System.Security.Cryptography.SHA256.Create();
                        var challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                        var challenge = Convert.ToBase64String(challengeBytes)
                            .Replace("+", "-")
                            .Replace("/", "_")
                            .TrimEnd('=');

                        if (challenge != session.CodeChallenge)
                        {
                            _logger.LogWarning("PKCE verification failed for S256");
                            return (null, null, null);
                        }
                    }
                    else
                    {
                        // Plain (not recommended, but supported by spec)
                        if (codeVerifier != session.CodeChallenge)
                        {
                            _logger.LogWarning("PKCE verification failed for plain");
                            return (null, null, null);
                        }
                    }
                }

                var validUser = await GetUserByEmailOrNationalIdAsync(session.EmailOrNationalId);
                if (validUser != null)
                {
                    validUser.Nonce = session.Nonce;
                }
                return (validUser, session.Scopes, session.AuthTime);
            }

            // Handle NETWORCO ID authorization codes
            if (code.StartsWith("dev_"))
            {
                var isRegistrationCode = code.Contains("_reg");
                if (isRegistrationCode)
                {
                    // For registration, create a new user with NETWORCO ID data
                    var simulatedUser = await CreateSimulatedUserForRegistrationAsync();
                    return (simulatedUser, new List<string> { "openid", "profile", "email" }, null);
                }
                else
                {
                    // For login, this would normally validate against existing users
                    // For now, return null to indicate no existing user found
                    return (null, null, null);
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
                return (null, null, null);

            var emailOrNationalId = parts[0];
            var originalRedirectUri = parts[1];
            
            string? originalClientId = null;
            long timestamp;
            List<string>? legacyScopes = new List<string> { "openid", "profile", "email" }; // Default for legacy

            if (parts.Length >= 4)
            {
                 // Check if index 2 is client ID or timestamp (legacy format variation)
                 // If parts.Length is 5, it likely includes scopes: email|uri|clientId|timestamp|scopes
                 if (parts.Length == 5)
                 {
                     originalClientId = parts[2];
                     timestamp = long.Parse(parts[3]);
                     var scopeString = parts[4];
                     if (!string.IsNullOrEmpty(scopeString))
                     {
                         legacyScopes = scopeString.Split(',').ToList();
                     }
                 }
                 else
                 {
                    originalClientId = parts[2];
                    timestamp = long.Parse(parts[3]);
                 }
            }
            else
            {
                // Legacy format
                timestamp = long.Parse(parts[2]);
            }

            // Verify redirect URI matches (case-insensitive for local development)
            var normalizedLegacyOriginal = originalRedirectUri.TrimEnd('/');
            var normalizedLegacyActual = redirectUri.TrimEnd('/');

            if (!string.Equals(normalizedLegacyOriginal, normalizedLegacyActual, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Authorization code validation failed: redirect_uri mismatch. Expected {Expected}, Got {Actual}", originalRedirectUri, redirectUri);
                return (null, null, null);
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
                    return (null, null, null);
                }
                
                _logger.LogInformation("Trusted API client {ApiClient} is exchanging code for client {OriginalClient}", clientId, originalClientId);
            }

            // Check expiration
            var codeAge = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp;
            if (codeAge > CodeExpiration.TotalSeconds)
                return (null, null, null);

            // Get user from database
            var user = await GetUserByEmailOrNationalIdAsync(emailOrNationalId);
            return (user, legacyScopes, null); 
        }
        catch
        {
            return (null, null, null);
        }
    }

    private async Task RevokeAllRefreshTokensForUserAsync(string emailOrNationalId)
    {
        try
        {
            var user = await GetUserByEmailOrNationalIdAsync(emailOrNationalId);
            if (user != null)
            {
                await InvalidateActiveSessionsAsync(user.Id);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke tokens for user {User}", emailOrNationalId);
        }
    }

    public async Task InvalidateActiveSessionsAsync(Guid userId)
    {
        // 1. Revoke refresh tokens so stale identity can't be renewed.
        var tokens = await _context.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ToListAsync();
        foreach (var t in tokens)
        {
            t.RevokedAt = DateTimeOffset.UtcNow;
        }

        // 2. Invalidate outstanding access tokens by bumping the credential timestamp —
        // the JWT validation hook rejects tokens issued before it. (No-op for accounts
        // without a password credential, e.g. BankID-only users; their short-lived access
        // tokens simply expire, and step 1 already cut off renewal.)
        var credentials = await _context.UserCredentials.FirstOrDefaultAsync(c => c.Id == userId);
        if (credentials != null)
        {
            credentials.UpdatedAt = DateTimeOffset.UtcNow;
            _context.UserCredentials.Update(credentials);
        }

        if (tokens.Count > 0 || credentials != null)
        {
            await _context.SaveChangesAsync();
            _logger.LogInformation("Invalidated active sessions for user {UserId} ({Count} refresh tokens revoked)", userId, tokens.Count);
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

    public async Task StoreRefreshTokenAsync(Guid userId, string tokenHash, DateTimeOffset expiresAt, string? clientId = null)
    {
        var refreshToken = new RefreshTokenEntity
        {
            UserId = userId,
            TokenHash = tokenHash,
            ExpiresAt = expiresAt,
            CreatedAt = DateTimeOffset.UtcNow,
            ClientId = clientId
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

        // If revoked, only a token superseded by ROTATION gets a brief grace window —
        // that's the case the grace exists for (tolerating concurrent-refresh races).
        // A token revoked WITHOUT a successor (ReplacedByTokenId == null) was killed
        // administratively — logout, reuse-detection, or session invalidation on email
        // change — and must be rejected immediately so a revoked identity can't be renewed.
        if (token.RevokedAt != null)
        {
            return token.ReplacedByTokenId != null &&
                   token.RevokedAt > DateTimeOffset.UtcNow.AddSeconds(-60) &&
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

        // Check expiration and revocation. Grace applies ONLY to rotation-superseded
        // tokens (ReplacedByTokenId set); administratively-revoked tokens (logout,
        // reuse-detection, session invalidation) are rejected immediately.
        var isValid = token.RevokedAt == null
            ? token.ExpiresAt > DateTimeOffset.UtcNow
            : token.ReplacedByTokenId != null
                && token.RevokedAt > DateTimeOffset.UtcNow.AddSeconds(-60)
                && token.ExpiresAt > DateTimeOffset.UtcNow;

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
            Roles = user.Roles,
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
        if (string.IsNullOrEmpty(emailOrNationalId) || string.IsNullOrEmpty(currentPassword) || string.IsNullOrEmpty(newPassword))
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

        // Add check for current password being same as new password
        // This is optional but good practice to prevent unnecessary updates if they just type the same thing
        // However, if we re-hash it, salt changes, so string compare of hash won't work. 
        // We must verify the new password against old hash to see if it's the same.
        if (_passwordHasher.VerifyPassword(newPassword, user.Credential.PasswordHash))
        {
             // New password is same as old
             _logger.LogWarning("ChangePassword for {Identifier}: New password is same as old password.", identifier);
             // We can either return false or just return true and pretend we did it. 
             // Returning false usually implies "current password wrong" or validation error.
             // Let's treat it as a success but skip the update to be idempotent-ish, or fail validation?
             // Usually policies say "New password must be different".
             // Let's fail it.
             // return false; 
             // Actually, strict OIDC doesn't mandate this, but security policies often do.
        }

        if (!_passwordHasher.VerifyPassword(currentPassword, user.Credential.PasswordHash))
        {
            _logger.LogWarning("ChangePassword failed for {Identifier}: Current password verification failed.", identifier);
            return false;
        }

        var validationResult = _passwordValidator.Validate(
            newPassword,
            _config.MinPasswordLength,
            _config.RequireDigit,
            _config.RequireUppercase,
            _config.RequireLowercase,
            _config.RequireNonAlphanumeric);
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

    public async Task<bool> InitiatePasswordResetAsync(string email, string? returnUrl = null)
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

        // Publish to NATS using the specialized message type for better worker handling.
        // ReturnUrl carries the OAuth params from the originating /Login through the
        // reset-email link → reset-password page → "Logg inn" button, so the user
        // lands back in the OAuth flow they started instead of a bare /Login.
        var resetMessage = new PasswordResetMessage(user.Email, token, user.FirstName, _config.BaseUrl, returnUrl);
        var jsonBytes = global::System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(resetMessage);
        
        _logger.LogInformation("Publishing password reset message to NATS: {Email} ({ByteCount} bytes)", user.Email, jsonBytes.Length);
        
        await _nats.PublishAsync(NetworcoIdSubjects.PasswordReset, jsonBytes);

        _logger.LogInformation("Password reset initiated for {Email}", email);
        await _auditService.LogAsync("PasswordResetInitiated", $"Password reset token generated for: {email}", user.Id);

        return true;
    }

    public async Task<bool> ResetPasswordWithTokenAsync(string token, string newPassword)
    {
        var user = await _context.Users
            .Include(u => u.Credential)
            .Where(u => u.PasswordResetToken == token
                && u.PasswordResetTokenExpiresAt > DateTimeOffset.UtcNow
                && u.IsActive)
            .FirstOrDefaultAsync();

        if (user == null)
        {
            // Covers an unknown/expired token AND a deactivated account — we don't
            // distinguish them to the caller (no account-status disclosure).
            _logger.LogWarning("Invalid or expired password reset token (or inactive account)");
            return false;
        }

        var validationResult = _passwordValidator.Validate(
            newPassword,
            _config.MinPasswordLength,
            _config.RequireDigit,
            _config.RequireUppercase,
            _config.RequireLowercase,
            _config.RequireNonAlphanumeric);
        if (!validationResult.IsValid)
        {
            throw new ArgumentException(validationResult.ErrorMessage);
        }

        var newHash = _passwordHasher.HashPassword(newPassword);
        if (user.Credential == null)
        {
            // Passwordless account — created via an external login (e.g. BankID/
            // Vipps via IDura) and never had a local password. A reset here is the
            // user setting their first password, so create the credential instead
            // of failing. Email ownership is proven by acting on the reset link.
            user.Credential = new UserCredentialEntity
            {
                Id = user.Id, // Same ID as user (1:1 relationship)
                PasswordHash = newHash,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            };
            _context.UserCredentials.Add(user.Credential);
        }
        else
        {
            user.Credential.PasswordHash = newHash;
            user.Credential.MustChangePassword = false;
            user.Credential.UpdatedAt = DateTimeOffset.UtcNow;
            user.Credential.FailedLoginAttempts = 0;
            user.Credential.LockedUntil = null;
            _context.UserCredentials.Update(user.Credential);
        }

        user.PasswordResetToken = null;
        user.PasswordResetTokenExpiresAt = null;

        // Completing a password reset is functionally email-ownership proof —
        // the user received the reset link in their inbox and acted on it.
        // Treating it as verification too means anyone who never finished the
        // initial verify flow can recover by resetting their password instead.
        if (!user.EmailVerified)
        {
            user.EmailVerified = true;
            user.EmailVerificationToken = null;
            user.EmailVerificationTokenExpiresAt = null;
            user.EmailVerificationSessionId = null;
            _logger.LogInformation("Marked email verified for {Id} via password-reset completion", user.Id);
        }

        _context.Users.Update(user);
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

}

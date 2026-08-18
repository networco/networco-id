using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using NetworcoId.Core.Security;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using NetworcoId.Infrastructure.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Services.Audit;
using NetworcoId.Services.Messaging;
using NetworcoId.Services.Security;
using NetworcoId.Pages;

namespace NetworcoId.Endpoints;

/// <summary>
/// Direct authentication endpoints.
/// Provides simple login/logout for development.
/// </summary>
public static class AuthEndpoints
{
    public static void MapAuth(this WebApplication app)
    {
        var group = app.MapGroup("/auth")
            .WithTags("🔑 Authentication")
            .WithDescription("Direct authentication endpoints for development");

        group.MapPost("/register", Register)
            .WithName("Register")
            .RequireRateLimiting("auth-strict")
            .WithSummary("Register new user")
            .WithDescription("""
                Register a new user account.
                Creates user identity in the authentication database.

                ### Request Body
                - `email` (required): User's email address
                - `password` (required): User's password
                - `firstName` (required): User's first name
                - `lastName` (required): User's last name
                - `nationalId` (optional): User's national ID
                - `phoneNumber` (optional): User's phone number
                """)
            .Produces<ValidationProblemDetails>(400)
            .Produces<AuthenticateResponse>(201)
            .AllowAnonymous();

        group.MapPost("/login", Login)
            .WithName("Login")
            .RequireRateLimiting("auth-strict")
            .WithSummary("Direct login")
            .WithDescription("""
                Direct user authentication.
                Returns access and refresh tokens.

                ### Request Body
                - `emailOrNationalId` (required): User's email or national ID
                - `password` (required): User's password
                """)
            .Produces<ValidationProblemDetails>(400)
            .Produces<AuthenticateResponse>(200)
            .AllowAnonymous();

        group.MapPost("/refresh", Refresh)
            .WithName("Refresh")
            .WithSummary("Refresh access token")
            .WithDescription("""
                Refresh an expired access token using a refresh token.

                ### Request Body
                - `refreshToken` (required): Valid refresh token
                """)
            .Produces<ValidationProblemDetails>(400)
            .Produces<RefreshTokenResponse>(200)
            .AllowAnonymous();

        group.MapPost("/logout", Logout)
            .WithName("Logout")
            .WithSummary("Logout user")
            .WithDescription("""
                Revoke the refresh token, effectively logging out the user.

                ### Request Body
                - `refreshToken` (required): Refresh token to revoke
                """)
            .Produces(204)
            .AllowAnonymous();

        group.MapGet("/me", GetCurrentUser)
            .WithName("GetCurrentUser")
            .WithSummary("Get current user info")
            .WithDescription("""
                Get information about the currently authenticated user.
                Requires valid access token in Authorization header.
                """)
            .Produces<NetworcoIdUserDto>(200)
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });

        group.MapPost("/me", GetCurrentUser)
            .WithName("GetCurrentUserPost")
            .WithSummary("Get current user info (POST)")
            .WithDescription("""
                Get information about the currently authenticated user.
                Requires valid access token in Authorization header.
                Supported for OIDC compliance.
                """)
            .Produces<NetworcoIdUserDto>(200)
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });

        // Self-service email management for the currently authenticated user.
        // Lets relying-party apps (e.g. the NETWORCO app) trigger verification and
        // email changes for a signed-in user without owning the email/verification
        // state themselves — NETWORCO ID stays the single source of truth.
        group.MapPost("/email/send-verification", SendEmailVerification)
            .WithName("SendEmailVerification")
            .RequireRateLimiting("auth-strict")
            .WithSummary("Resend the email-verification link for the current user")
            .WithDescription("""
                (Re)issues an email-verification link to the currently authenticated
                user's email address. No-op (200) if the email is already verified.
                Requires a valid access token in the Authorization header.
                """)
            .Produces(200)
            .Produces(400)
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });

        group.MapPut("/email", ChangeEmail)
            .WithName("ChangeEmail")
            .RequireRateLimiting("auth-strict")
            .WithSummary("Change the current user's email and send a verification link")
            .WithDescription("""
                Updates the authenticated user's email address (e.g. replacing a
                generated @id.networco.no placeholder), marks it unverified, and
                sends a verification link to the new address.

                ### Request Body
                - `email` (required): the new email address
                - `returnUrl` (optional): where to send the user after verification
                """)
            .Produces(200)
            .Produces(400)
            .Produces(409)
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });

        group.MapGet("/external-logins", GetExternalLogins)
            .WithName("GetExternalLogins")
            .WithSummary("List the current user's external (BankID/IDura) login references")
            .WithDescription("""
                Returns the federated login references (provider + subject) linked to
                the authenticated user. Exposed over the authenticated back-channel so
                relying parties can record the BankID/IDura reference server-side
                without it ever appearing in a JWT.
                """)
            .Produces<ExternalLoginsResponse>(200)
            .RequireRateLimiting("auth-strict")
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme });

        group.MapPost("/forgot-password", ForgotPassword)
            .WithName("ForgotPassword")
            .RequireRateLimiting("auth-strict")
            .WithSummary("Initiate password reset")
            .Produces(200)
            .AllowAnonymous();

        group.MapPost("/reset-password", ResetPassword)
            .WithName("ResetPassword")
            .RequireRateLimiting("auth-strict")
            .WithSummary("Complete password reset")
            .Produces(200)
            .Produces(400)
            .AllowAnonymous();

        // JWKS Endpoint
        group.MapGet("/.well-known/jwks.json", GetJwks)
            .WithName("GetJwks")
            .WithSummary("Get JSON Web Key Set")
            .WithDescription("Returns public keys for validating JWT tokens")
            .Produces<Microsoft.IdentityModel.Tokens.JsonWebKeySet>(200)
            .AllowAnonymous();
    }

    private static async Task<IResult> GetJwks(IJwtService jwtService)
    {
        var keys = await jwtService.GetPublicKeysAsync();
        return Results.Ok(keys);
    }

    private static async Task<IResult> ForgotPassword(
        [FromBody] ForgotPasswordRequest request,
        IAuthService authService)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return Results.BadRequest(new { error = "Email is required" });
        }

        await authService.InitiatePasswordResetAsync(request.Email);
        return Results.Ok(new { message = "If the email exists, a reset link has been sent." });
    }

    private static async Task<IResult> ResetPassword(
        [FromBody] ResetPasswordRequest request,
        IAuthService authService,
        ILockoutService lockoutService,
        HttpContext httpContext)
    {
        if (string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return Results.BadRequest(new { error = "Token and NewPassword are required" });
        }

        var result = await authService.ResetPasswordWithTokenAsync(request.Token, request.NewPassword);
        if (!result)
        {
            return Results.BadRequest(new { error = "Invalid or expired reset token" });
        }

        // A completed reset proves account ownership — drop the IP throttle so the
        // user isn't blocked by leftover failures from before the reset.
        await lockoutService.ResetAsync(httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

        return Results.Ok(new { message = "Password has been successfully reset." });
    }

    private static async Task<IResult> Login(
        [FromBody] AuthenticateRequest request,
        IAuthService authService,
        IJwtService jwtService,
        NetworcoIdConfig config)
    {
        if (string.IsNullOrWhiteSpace(request.EmailOrNationalId) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.BadRequest(new { error = "Email/National ID and password are required" });
        }

        var user = await authService.AuthenticateUserAsync(request.EmailOrNationalId, request.Password);
        if (user == null)
        {
            return Results.BadRequest(new { error = "Invalid credentials" });
        }

        if (user.MustChangePassword)
        {
            return Results.Json(new { error = "must_change_password", message = "You must change your password before proceeding." }, statusCode: 403);
        }

        var accessToken = await jwtService.GenerateAccessTokenAsync(user, config.Audience);
        var refreshToken = jwtService.GenerateRefreshToken();

        // Store refresh token
        var refreshTokenHash = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(refreshToken)));
        await authService.StoreRefreshTokenAsync(
            user.Id,
            refreshTokenHash,
            DateTimeOffset.UtcNow.AddDays(config.RefreshTokenExpirationDays));

        return Results.Ok(new AuthenticateResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = config.AccessTokenExpirationMinutes * 60,
            TokenType = "Bearer",
            User = user
        });
    }

    private static async Task<IResult> Refresh(
        [FromBody] RefreshTokenRequest request,
        IAuthService authService,
        IJwtService jwtService,
        NetworcoIdConfig config)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return Results.BadRequest(new { error = "Refresh token is required" });
        }

        var refreshTokenHash = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(request.RefreshToken)));

        var isValid = await authService.ValidateRefreshTokenAsync(refreshTokenHash);
        if (!isValid)
        {
            return Results.BadRequest(new { error = "Invalid or expired refresh token" });
        }

        var user = await authService.GetUserByRefreshTokenAsync(refreshTokenHash);
        if (user == null)
        {
            return Results.BadRequest(new { error = "User not found or refresh token invalid" });
        }

        // Generate new tokens
        var newAccessToken = await jwtService.GenerateAccessTokenAsync(user, config.Audience);
        var newRefreshToken = jwtService.GenerateRefreshToken();

        // Rotate refresh token
        var newRefreshTokenHash = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(newRefreshToken)));
        await authService.RotateRefreshTokenAsync(
            refreshTokenHash,
            newRefreshTokenHash,
            DateTimeOffset.UtcNow.AddDays(config.RefreshTokenExpirationDays));

        return Results.Ok(new RefreshTokenResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            ExpiresIn = config.AccessTokenExpirationMinutes * 60,
            TokenType = "Bearer",
            User = user
        });
    }

    private static async Task<IResult> Register(
        [FromBody] RegisterRequest request,
        IAuthService authService,
        IJwtService jwtService,
        NetworcoIdConfig config)
    {
        if (string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password) ||
            string.IsNullOrWhiteSpace(request.FirstName) ||
            string.IsNullOrWhiteSpace(request.LastName))
        {
            return Results.BadRequest(new { error = "Email, password, first name, and last name are required" });
        }

        try
        {
            var user = await authService.RegisterUserAsync(
                request.Email,
                request.Password,
                request.FirstName,
                request.LastName,
                request.NationalId,
                request.PhoneNumber);

            if (user == null)
            {
                return Results.BadRequest(new { error = "Failed to create user account" });
            }

            var accessToken = await jwtService.GenerateAccessTokenAsync(user, config.Audience);
            var refreshToken = jwtService.GenerateRefreshToken();

            // Store refresh token
            var refreshTokenHash = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(refreshToken)));
            await authService.StoreRefreshTokenAsync(
                user.Id,
                refreshTokenHash,
                DateTimeOffset.UtcNow.AddDays(config.RefreshTokenExpirationDays));

            return Results.Created($"/auth/me", new AuthenticateResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = config.AccessTokenExpirationMinutes * 60,
                TokenType = "Bearer",
                User = user
            });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> Logout(
        [FromBody] RefreshTokenRequest request,
        IAuthService authService)
    {
        if (!string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            var refreshTokenHash = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(request.RefreshToken)));
            await authService.RevokeRefreshTokenAsync(refreshTokenHash);
        }

        return Results.NoContent();
    }

    private static Guid? GetAuthenticatedUserId(HttpContext context)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        return Guid.TryParse(sub, out var id) ? id : null;
    }

    private static bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return string.Equals(addr.Address, email, StringComparison.Ordinal) && email.Contains('.');
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Normalizes a caller-supplied post-verification return target to something safe to embed
    /// in a verification email. The verify page turns this value into a redirect (and, on
    /// same-browser verification, mints an authorization code for it), so an unvalidated value
    /// would be an open-redirect / code-injection vector. We allow only a frontend-relative
    /// path or an absolute URL on the configured frontend origin; anything else falls back to
    /// the frontend root.
    /// </summary>
    private static string SafeReturnUrl(string? returnUrl, NetworcoIdConfig config)
    {
        var frontend = (config.FrontendUrl ?? string.Empty).TrimEnd('/');
        if (string.IsNullOrWhiteSpace(returnUrl)) return frontend;

        var candidate = returnUrl.Trim();

        // Frontend-relative path ("/...") — but not protocol-relative ("//host").
        if (candidate.StartsWith('/') && !candidate.StartsWith("//"))
            return frontend + candidate;

        // Absolute URL — only if it's on the configured frontend origin.
        if (Uri.TryCreate(candidate, UriKind.Absolute, out var abs)
            && Uri.TryCreate(frontend, UriKind.Absolute, out var fe)
            && string.Equals(abs.Scheme, fe.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(abs.Authority, fe.Authority, StringComparison.OrdinalIgnoreCase))
        {
            return candidate;
        }

        return frontend;
    }

    private static async Task<IResult> SendEmailVerification(
        HttpContext context,
        AuthDbContext db,
        IEmailService emailService,
        NetworcoIdConfig config,
        [FromBody] SendVerificationRequest? request)
    {
        var userId = GetAuthenticatedUserId(context);
        if (userId is null) return Results.Unauthorized();

        var user = await db.Users.AsTracking().FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return Results.BadRequest(new { error = "user_not_found" });
        if (user.EmailVerified)
            return Results.Ok(new { status = "already_verified", email = user.Email });

        var returnUrl = SafeReturnUrl(request?.ReturnUrl, config);
        await EmailVerificationHelper.SendAsync(context, db, emailService, user, config.BaseUrl, returnUrl);
        return Results.Ok(new { status = "sent", email = user.Email });
    }

    private static async Task<IResult> ChangeEmail(
        HttpContext context,
        AuthDbContext db,
        IEmailService emailService,
        IAuditService audit,
        IAuthService authService,
        NetworcoIdConfig config,
        [FromBody] ChangeEmailRequest request)
    {
        var userId = GetAuthenticatedUserId(context);
        if (userId is null) return Results.Unauthorized();

        var newEmail = request?.Email?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(newEmail) || !IsValidEmail(newEmail))
            return Results.BadRequest(new { error = "invalid_email" });

        var user = await db.Users.AsTracking().FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return Results.BadRequest(new { error = "user_not_found" });

        // Already this exact (verified) address — nothing to do.
        if (string.Equals(user.Email, newEmail, StringComparison.OrdinalIgnoreCase) && user.EmailVerified)
            return Results.Ok(new { status = "unchanged", email = user.Email, emailVerified = user.EmailVerified });

        // Uniqueness: no *other* user may already hold this address.
        var lower = newEmail.ToLowerInvariant();
        var taken = await db.Users.AsNoTracking()
            .AnyAsync(u => u.Id != userId && u.Email != null && u.Email.ToLower() == lower);
        if (taken) return Results.Conflict(new { error = "email_taken" });

        user.Email = newEmail;
        user.EmailVerified = false;
        user.EmailVerificationToken = null;
        user.EmailVerificationTokenExpiresAt = null;
        user.EmailVerificationSessionId = null;
        await db.SaveChangesAsync();
        await audit.LogAsync("EmailChanged", $"Email changed via self-service to {newEmail}", user.Id);

        // The identity changed (new, now-unverified address). Tear down outstanding
        // access/refresh tokens so nothing keeps asserting the old (verified) email; the
        // user re-authenticates against the new address.
        await authService.InvalidateActiveSessionsAsync(user.Id);

        var returnUrl = SafeReturnUrl(request?.ReturnUrl, config);
        await EmailVerificationHelper.SendAsync(context, db, emailService, user, config.BaseUrl, returnUrl);

        return Results.Ok(new { status = "verification_sent", email = user.Email, emailVerified = false });
    }

    private static async Task<IResult> GetExternalLogins(HttpContext context, AuthDbContext db)
    {
        var userId = GetAuthenticatedUserId(context);
        if (userId is null) return Results.Unauthorized();

        // BankID is authoritative for the birth date and is stored on the user (string "YYYY-MM-DD").
        var birthDate = await db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => u.BirthDate)
            .FirstOrDefaultAsync();

        var logins = await db.UserExternalLogins.AsNoTracking()
            .Where(l => l.UserId == userId)
            .OrderByDescending(l => l.LastLoginAt)
            .Select(l => new ExternalLoginRef(l.Provider, l.Subject, l.FirstName, l.LastName, birthDate, l.LastLoginAt, l.CreatedAt))
            .ToListAsync();

        return Results.Ok(new ExternalLoginsResponse(logins));
    }

    private static IResult GetCurrentUser(HttpContext context)
    {
        // Extract user info from JWT token claims
        var userId = context.User.FindFirst("sub")?.Value;
        
        // DEBUG LOGGING
        Console.WriteLine($"[GetCurrentUser] User ID: {userId}");
        foreach (var claim in context.User.Claims)
        {
            Console.WriteLine($"[GetCurrentUser] Claim: {claim.Type} = {claim.Value}");
        }

        var claims = new Dictionary<string, object>
        {
            { "sub", userId ?? "" }
        };

        // Determine authorized scopes from the token
        var scopeClaim = context.User.FindFirst("scope")?.Value;
        Console.WriteLine($"[GetCurrentUser] Scope Claim: {scopeClaim}");
        
        var scopes = scopeClaim?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet() 
                     ?? new HashSet<string>();
        
        Console.WriteLine($"[GetCurrentUser] Parsed Scopes: {string.Join(", ", scopes)}");

        if (scopes.Contains("email"))
        {
            Console.WriteLine("[GetCurrentUser] Scope 'email' present. Checking for claim...");
            if (context.User.HasClaim(c => c.Type == "email"))
            {
                var email = context.User.FindFirst("email")?.Value;
                Console.WriteLine($"[GetCurrentUser] Claim 'email' found: {email}");
                if (!string.IsNullOrEmpty(email))
                    claims.Add("email", email);
            }
            else
            {
                Console.WriteLine("[GetCurrentUser] Claim 'email' NOT found in Principal.");
            }
        }
        else
        {
            Console.WriteLine("[GetCurrentUser] Scope 'email' NOT present.");
        }

        if (scopes.Contains("email") && context.User.HasClaim(c => c.Type == "email_verified"))
        {
            var emailVerified = context.User.FindFirst("email_verified")?.Value;
            if (bool.TryParse(emailVerified, out var isVerified))
                claims.Add("email_verified", isVerified);
        }

        if (scopes.Contains("profile"))
        {
            if (context.User.HasClaim(c => c.Type == "given_name"))
            {
                var givenName = context.User.FindFirst("given_name")?.Value;
                if (!string.IsNullOrEmpty(givenName))
                    claims.Add("given_name", givenName);
            }

            if (context.User.HasClaim(c => c.Type == "family_name"))
            {
                var familyName = context.User.FindFirst("family_name")?.Value;
                if (!string.IsNullOrEmpty(familyName))
                    claims.Add("family_name", familyName);
            }

            // Add 'name' claim if present in the token (meaning 'profile' scope was requested)
            if (context.User.HasClaim(c => c.Type == "name"))
            {
                var name = context.User.FindFirst("name")?.Value;
                if (!string.IsNullOrEmpty(name))
                    claims.Add("name", name);
            }

            if (context.User.HasClaim(c => c.Type == "birthdate"))
            {
                var birthdate = context.User.FindFirst("birthdate")?.Value;
                if (!string.IsNullOrEmpty(birthdate))
                    claims.Add("birthdate", birthdate);
            }
            
            // Add preferred_username if present in token
            if (context.User.HasClaim(c => c.Type == "preferred_username"))
            {
                var preferredUsername = context.User.FindFirst("preferred_username")?.Value;
                if (!string.IsNullOrEmpty(preferredUsername))
                    claims.Add("preferred_username", preferredUsername);
            }

            // Add updated_at claim if present in token
            if (context.User.HasClaim(c => c.Type == "updated_at"))
            {
                var updatedAt = context.User.FindFirst("updated_at")?.Value;
                // Try parse to long to ensure valid JSON number format if needed, though value usually string in Claim
                if (long.TryParse(updatedAt, out var updatedAtLong))
                    claims.Add("updated_at", updatedAtLong);
            }

            if (context.User.HasClaim(c => c.Type == "national_id"))
            {
                var nationalId = context.User.FindFirst("national_id")?.Value;
                if (!string.IsNullOrEmpty(nationalId))
                    claims.Add("national_id", nationalId);
            }
        }

        if (scopes.Contains("phone"))
        {
            if (context.User.HasClaim(c => c.Type == "phone_number"))
            {
                var phoneNumber = context.User.FindFirst("phone_number")?.Value;
                if (!string.IsNullOrEmpty(phoneNumber))
                    claims.Add("phone_number", phoneNumber);
            }
            
            if (context.User.HasClaim(c => c.Type == "phone_number_verified"))
            {
                var phoneVerified = context.User.FindFirst("phone_number_verified")?.Value;
                if (bool.TryParse(phoneVerified, out var isVerified))
                    claims.Add("phone_number_verified", isVerified);
            }
        }

        if (scopes.Contains("address"))
        {
            // OIDC spec requires address to be a JSON object.
            // Even if we don't have address data, we must return the claim key if the scope is granted.
            // The value should be a JSON object, even if empty.
            
            if (context.User.HasClaim(c => c.Type == "address"))
            {
                var addressJson = context.User.FindFirst("address")?.Value;
                try 
                {
                    if (!string.IsNullOrEmpty(addressJson))
                    {
                        var deserialized = System.Text.Json.JsonSerializer.Deserialize<IDictionary<string, object>>(addressJson);
                        if (deserialized != null)
                        {
                            claims.Add("address", deserialized);
                        }
                    }
                }
                catch
                {
                    // Fallback if parsing fails or empty
                    claims.Add("address", new 
                    {
                        formatted = "",
                        street_address = "",
                        locality = "",
                        region = "",
                        postal_code = "",
                        country = ""
                    });
                }
            }
            else 
            {
                // Ensure address object exists if scope is granted but claim missing
                claims.Add("address", new 
                {
                    formatted = "",
                    street_address = "",
                    locality = "",
                    region = "",
                    postal_code = "",
                    country = ""
                });
            }
        }
        
        // Handle case where scope might be missing (e.g. client creds or old tokens)
        // If no scopes are present, default to minimal claims (sub only), which is already set

        return Results.Json(claims);
    }
}

/// <summary>Body for POST /auth/email/send-verification.</summary>
public record SendVerificationRequest(string? ReturnUrl);

/// <summary>Body for PUT /auth/email.</summary>
public record ChangeEmailRequest(string Email, string? ReturnUrl);

/// <summary>A single federated login reference for the current user.</summary>
public record ExternalLoginRef(string Provider, string Subject, string? FirstName, string? LastName, string? BirthDate, DateTimeOffset? LastLoginAt, DateTimeOffset CreatedAt);

/// <summary>Response for GET /auth/external-logins.</summary>
public record ExternalLoginsResponse(IReadOnlyList<ExternalLoginRef> ExternalLogins);

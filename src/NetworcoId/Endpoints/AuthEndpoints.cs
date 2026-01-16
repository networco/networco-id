using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using NetworcoId.Core.Security;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using NetworcoId.Infrastructure.Auth;

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
            .WithDescription("Direct authentication endpoints for development")
            .AllowAnonymous();

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
            .Produces<AuthenticateResponse>(201);

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
            .Produces<AuthenticateResponse>(200);

        group.MapPost("/refresh", Refresh)
            .WithName("Refresh")
            .WithSummary("Refresh access token")
            .WithDescription("""
                Refresh an expired access token using a refresh token.

                ### Request Body
                - `refreshToken` (required): Valid refresh token
                """)
            .Produces<ValidationProblemDetails>(400)
            .Produces<RefreshTokenResponse>(200);

        group.MapPost("/logout", Logout)
            .WithName("Logout")
            .WithSummary("Logout user")
            .WithDescription("""
                Revoke the refresh token, effectively logging out the user.

                ### Request Body
                - `refreshToken` (required): Refresh token to revoke
                """)
            .Produces(204);

        group.MapGet("/me", GetCurrentUser)
            .WithName("GetCurrentUser")
            .WithSummary("Get current user info")
            .WithDescription("""
                Get information about the currently authenticated user.
                Requires valid access token in Authorization header.
                """)
            .Produces<NetworcoIdUserDto>(200)
            .RequireAuthorization();

        group.MapPost("/forgot-password", ForgotPassword)
            .WithName("ForgotPassword")
            .RequireRateLimiting("auth-strict")
            .WithSummary("Initiate password reset")
            .Produces(200);

        group.MapPost("/reset-password", ResetPassword)
            .WithName("ResetPassword")
            .RequireRateLimiting("auth-strict")
            .WithSummary("Complete password reset")
            .Produces(200)
            .Produces(400);
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
        IAuthService authService)
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

        var accessToken = jwtService.GenerateAccessToken(user);
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
        var newAccessToken = jwtService.GenerateAccessToken(user);
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

            var accessToken = jwtService.GenerateAccessToken(user);
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

    private static IResult GetCurrentUser(HttpContext context)
    {
        // Extract user info from JWT token claims
        var userId = context.User.FindFirst("sub")?.Value;
        var user = new NetworcoIdUserDto
        {
            Id = Guid.TryParse(userId, out var id) ? id : Guid.Empty,
            Email = context.User.FindFirst("email")?.Value ?? "",
            FirstName = context.User.FindFirst("given_name")?.Value ?? "",
            LastName = context.User.FindFirst("family_name")?.Value ?? "",
            NationalId = context.User.FindFirst("national_id")?.Value ?? "",
            // Removed: Role - authorization handled by resource server
        };

        return Results.Ok(user);
    }
}
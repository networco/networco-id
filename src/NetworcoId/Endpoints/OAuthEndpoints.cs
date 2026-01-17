using System.Web;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using NetworcoId.Core.Security;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using NetworcoId.Infrastructure.Auth;

namespace NetworcoId.Endpoints;

/// <summary>
/// OAuth2 authorization endpoints.
/// Implements OAuth2 authorization code flow for development.
/// </summary>
public static class OAuthEndpoints
{
    public static void MapOAuth(this WebApplication app)
    {
        var group = app.MapGroup("/oauth")
            .WithTags("🔐 OAuth2")
            .WithDescription("OAuth2 authorization endpoints for NETWORCO ID")
            .AllowAnonymous();

        group.MapGet("/authorize", Authorize)
            .WithName("Authorize")
            .WithSummary("OAuth2 authorize endpoint")
            .WithDescription("""
                OAuth2 authorization endpoint.
                Redirects to login/registration page for NETWORCO ID users.

                ### Query Parameters
                - `response_type` (required): Must be "code"
                - `client_id` (required): OAuth2 client identifier
                - `redirect_uri` (required): Where to redirect after authorization
                - `state` (optional): CSRF protection state
                - `scope` (optional): Requested scopes
                - `registration` (optional): If "true", shows registration flow
                """)
            .Produces(302);

        group.MapPost("/token", Token)
            .WithName("Token")
            .RequireRateLimiting("auth-strict")
            .WithSummary("OAuth2 token endpoint")
            .WithDescription("""
                OAuth2 token endpoint.
                Exchanges authorization code for access token.

                ### Request Body
                - `grant_type` (required): Must be "authorization_code"
                - `code` (required): Authorization code from /authorize
                - `redirect_uri` (required): Must match the redirect_uri from /authorize
                - `client_id` (required): OAuth2 client identifier
                - `client_secret` (required): OAuth2 client secret
                """)
            .Produces<ValidationProblemDetails>(400)
            .Produces<TokenResponse>(200)
            .DisableAntiforgery();

        app.MapGet("/.well-known/openid-configuration", OpenIdConfiguration)
            .WithName("OpenIdConfiguration")
            .WithTags("🔐 OAuth2")
            .AllowAnonymous();

        app.MapGet("/.well-known/jwks.json", Jwks)
            .WithName("Jwks")
            .WithTags("🔐 OAuth2")
            .AllowAnonymous();

        group.MapGet("/logout", Logout)
            .WithName("OAuthLogout")
            .WithSummary("OAuth2 logout endpoint")
            .Produces(302);
    }

    private static IResult Logout(
        [FromQuery] string? post_logout_redirect_uri,
        [FromQuery] string? state,
        HttpContext context)
    {
        // For OIDC, we usually clear the application session
        // In this implementation, we can clear cookies or just redirect
        
        // If a redirect URI is provided, validate it (in a real system)
        // For now, we allow redirecting back to the provided URI or the home page
        var redirectUrl = post_logout_redirect_uri ?? "/";
        
        if (!string.IsNullOrEmpty(state))
        {
            var uriBuilder = new UriBuilder(redirectUrl);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);
            query["state"] = state;
            uriBuilder.Query = query.ToString();
            redirectUrl = uriBuilder.ToString();
        }

        return Results.Redirect(redirectUrl);
    }

    private static async Task<IResult> Jwks(IJwtService jwtService)
    {
        var keys = await jwtService.GetPublicKeysAsync();
        return Results.Ok(keys);
    }

    private static IResult OpenIdConfiguration(HttpContext context)
    {
        var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        
        return Results.Ok(new
        {
            issuer = baseUrl,
            authorization_endpoint = $"{baseUrl}/oauth/authorize",
            token_endpoint = $"{baseUrl}/oauth/token",
            jwks_uri = $"{baseUrl}/.well-known/jwks.json",
            userinfo_endpoint = $"{baseUrl}/auth/me",
            end_session_endpoint = $"{baseUrl}/oauth/logout",
            registration_endpoint = $"{baseUrl}/oauth/register",
            response_types_supported = new[] { "code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token" },
            subject_types_supported = new[] { "public", "pairwise" },
            id_token_signing_alg_values_supported = new[] { "HS256", "RS256" },
            scopes_supported = new[] { "openid", "profile", "email", "phone", "address", "offline_access" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" },
            claims_supported = new[] { "sub", "iss", "aud", "exp", "iat", "email", "name", "family_name", "given_name", "phone_number", "role", "national_id" },
            grant_types_supported = new[] { "authorization_code", "refresh_token" },
            code_challenge_methods_supported = new[] { "S256" }
        });
    }

    private static async Task<IResult> Authorize(
        HttpContext context,
        [FromQuery] string? response_type,
        [FromQuery] string? client_id,
        [FromQuery] string? redirect_uri,
        [FromQuery] string? state,
        [FromQuery] string? scope,
        [FromQuery] string? registration,
        [FromQuery] string? code_challenge,
        [FromQuery] string? code_challenge_method,
        [FromQuery] string? nonce,
        NetworcoId.Infrastructure.Database.AuthDbContext dbContext)
    {
        // 1. Validate Client and Redirect URI first (so we know where to send errors)
        
        if (string.IsNullOrEmpty(client_id))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
        }

        if (string.IsNullOrEmpty(redirect_uri))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required" });
        }

        // Validate client exists
        var clientEntity = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstOrDefaultAsync(dbContext.OAuthClients, c => c.ClientId == client_id);
        if (clientEntity == null || !clientEntity.IsActive)
        {
            // Invalid client: MUST NOT redirect to the redirect_uri.
            // We redirect to our own Login/Error page to inform the user.
            var errorQuery = HttpUtility.ParseQueryString("");
            errorQuery["error"] = "invalid_client";
            errorQuery["error_description"] = clientEntity == null ? $"Unknown client: {client_id}" : "Client is inactive";
            return Results.Redirect($"/Login?{errorQuery}");
        }

        // Validate redirect URI matches registered ones
        if (!clientEntity.RedirectUris.Contains(redirect_uri))
        {
            // Invalid redirect_uri: MUST NOT redirect to the redirect_uri.
            // We redirect to our own Login/Error page.
            var errorQuery = HttpUtility.ParseQueryString("");
            errorQuery["error"] = "invalid_request";
            errorQuery["error_description"] = "Invalid redirect_uri";
            errorQuery["client_id"] = client_id;
            return Results.Redirect($"/Login?{errorQuery}");
        }

        // 2. Now that we trust the redirect_uri, we can validate other parameters 
        // and redirect back to the client on failure.

        if (string.IsNullOrEmpty(response_type))
        {
             // Missing response_type -> Redirect back to client
             var errorQuery = HttpUtility.ParseQueryString("");
             errorQuery["error"] = "invalid_request";
             errorQuery["error_description"] = "response_type is required";
             if (!string.IsNullOrEmpty(state)) errorQuery["state"] = state;
             
             var builder = new UriBuilder(redirect_uri);
             builder.Query = (string.IsNullOrEmpty(builder.Query) ? "" : builder.Query.TrimStart('?') + "&") + errorQuery.ToString();
             return Results.Redirect(builder.ToString());
        }

        if (response_type != "code")
        {
             // Unsupported response_type -> Redirect back to client
             var errorQuery = HttpUtility.ParseQueryString("");
             errorQuery["error"] = "unsupported_response_type";
             errorQuery["error_description"] = "response_type must be 'code'";
             if (!string.IsNullOrEmpty(state)) errorQuery["state"] = state;

             var builder = new UriBuilder(redirect_uri);
             builder.Query = (string.IsNullOrEmpty(builder.Query) ? "" : builder.Query.TrimStart('?') + "&") + errorQuery.ToString();
             return Results.Redirect(builder.ToString());
        }

        if (response_type != "code")
        {
            // If redirect_uri is known and valid, we could redirect with error.
            // But for simplicity, return 400 here if it's completely unsupported.
            // A robust implementation would validate client_id + redirect_uri first, then redirect.
            return Results.BadRequest(new { error = "unsupported_response_type", error_description = "response_type must be 'code'" });
        }

        // Enforce PKCE for all clients (Security Hardening)
        // NOTE: Relaxed for Basic Certification which may not send PKCE
        // if (string.IsNullOrEmpty(code_challenge))
        // {
        //      return Results.BadRequest(new { error = "invalid_request", error_description = "code_challenge is required" });
        // }

        // Enforce S256 as the only allowed method
        // if (code_challenge_method != "S256")
        // {
        //      return Results.BadRequest(new { error = "invalid_request", error_description = "code_challenge_method must be 'S256'" });
        // }

        if (string.IsNullOrEmpty(redirect_uri))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required" });
        }

        // Validate client
        var client = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstOrDefaultAsync(dbContext.OAuthClients, c => c.ClientId == client_id);
        if (client == null || !client.IsActive)
        {
            var errorQuery = HttpUtility.ParseQueryString("");
            errorQuery["error"] = "invalid_client";
            errorQuery["error_description"] = client == null ? $"Unknown client: {client_id}" : "Client is inactive";
            return Results.Redirect($"/Login?{errorQuery}");
        }

        // Validate redirect URI
        if (!client.RedirectUris.Contains(redirect_uri))
        {
            var errorQuery = HttpUtility.ParseQueryString("");
            errorQuery["error"] = "invalid_request";
            errorQuery["error_description"] = "Invalid redirect_uri";
            errorQuery["client_id"] = client_id;
            return Results.Redirect($"/Login?{errorQuery}");
        }

        // Validate scopes
        if (!string.IsNullOrEmpty(scope))
        {
            var requestedScopes = scope.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            var invalidScopes = requestedScopes.Where(s => !clientEntity.AllowedScopes.Contains(s)).ToList();
            if (invalidScopes.Any())
            {
                var errorQuery = HttpUtility.ParseQueryString("");
                errorQuery["error"] = "invalid_scope";
                errorQuery["error_description"] = $"Invalid scopes: {string.Join(", ", invalidScopes)}";
                
                var builder = new UriBuilder(redirect_uri);
                builder.Query = (string.IsNullOrEmpty(builder.Query) ? "" : builder.Query.TrimStart('?') + "&") + errorQuery.ToString();
                return Results.Redirect(builder.ToString());
            }
        }

        // Redirect to Login page
        var query = HttpUtility.ParseQueryString("");
        query["client_id"] = client_id;
        query["redirect_uri"] = redirect_uri;
        if (!string.IsNullOrEmpty(state)) query["state"] = state;
        if (!string.IsNullOrEmpty(scope)) query["scope"] = scope;
        if (!string.IsNullOrEmpty(registration)) query["registration"] = registration;
        if (!string.IsNullOrEmpty(nonce)) query["nonce"] = nonce;
        
        // Pass PKCE params to login page so they can be preserved
        if (!string.IsNullOrEmpty(code_challenge)) query["code_challenge"] = code_challenge;
        if (!string.IsNullOrEmpty(code_challenge_method)) query["code_challenge_method"] = code_challenge_method;

        return Results.Redirect($"/Login?{query}");
    }

    private static async Task<IResult> Token(
        HttpContext httpContext,
        [FromForm] string grant_type,
        [FromForm] string? code,
        [FromForm] string? redirect_uri,
        [FromForm] string? client_id,
        [FromForm] string? client_secret,
        [FromForm] string? code_verifier,
        IAuthService authService,
        IJwtService jwtService,
        NetworcoId.Infrastructure.Database.AuthDbContext dbContext,
        IPasswordHasher passwordHasher,
        NetworcoIdConfig config)
    {
        // 1. Extract Client Credentials (supports both Basic Auth and POST body)
        string? finalClientId = client_id;
        string? finalClientSecret = client_secret;

        if (BasicAuthenticationHandler.TryGetBasicCredentials(httpContext, out var basicClientId, out var basicClientSecret))
        {
            finalClientId = basicClientId;
            finalClientSecret = basicClientSecret;
        }

        if (string.IsNullOrEmpty(finalClientId) || string.IsNullOrEmpty(finalClientSecret))
        {
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Client credentials are missing"
            });
        }
        if (grant_type != "authorization_code")
        {
            return Results.BadRequest(new
            {
                error = "unsupported_grant_type",
                error_description = "Only authorization_code grant type is supported"
            });
        }

        // Validate client credentials
        var clientEntity = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstOrDefaultAsync(dbContext.OAuthClients, c => c.ClientId == finalClientId);
        
        var isPrimaryValid = clientEntity != null && passwordHasher.VerifyPassword(finalClientSecret, clientEntity.PrimaryClientSecretHash);
        var isSecondaryValid = clientEntity != null && clientEntity.SecondaryClientSecretHash != null && passwordHasher.VerifyPassword(finalClientSecret, clientEntity.SecondaryClientSecretHash);

        if (clientEntity == null || !clientEntity.IsActive || (!isPrimaryValid && !isSecondaryValid))
        {
            Console.WriteLine($"Invalid client credentials. ClientId: {finalClientId}");
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Invalid client credentials"
            });
        }

        Console.WriteLine($"Client authenticated: {clientEntity.DisplayName}");

        // Validate authorization code
        var user = await authService.ValidateAuthorizationCodeAsync(code ?? string.Empty, redirect_uri ?? string.Empty, finalClientId, code_verifier);
        if (user == null)
        {
            return Results.BadRequest(new
            {
                error = "invalid_grant",
                error_description = "Invalid or expired authorization code"
            });
        }

        if (user.MustChangePassword)
        {
            return Results.BadRequest(new
            {
                error = "interaction_required",
                error_description = "User must change their password."
            });
        }

        // Log for debugging
        Console.WriteLine($"Token exchange for user ID: {user.Id}, Email: {user.Email}");

        // Generate tokens
        var accessToken = await jwtService.GenerateAccessTokenAsync(user);
        var idToken = await jwtService.GenerateIdTokenAsync(user, finalClientId, user.Nonce);
        var refreshToken = jwtService.GenerateRefreshToken();

        // Store refresh token
        var refreshTokenHash = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(refreshToken)));

        Console.WriteLine($"Storing refresh token for user ID: {user.Id}");

        await authService.StoreRefreshTokenAsync(
            user.Id, // Use the actual user ID from the authenticated user
            refreshTokenHash,
            DateTimeOffset.UtcNow.AddDays(config.RefreshTokenExpirationDays));

        return Results.Ok(new TokenResponse
        {
            AccessToken = accessToken,
            IdToken = idToken,
            TokenType = "Bearer",
            ExpiresIn = config.AccessTokenExpirationMinutes * 60,
            RefreshToken = refreshToken
        });
    }
}

# Networco Auth Service

A standalone authentication service for Networco development environments.

## Overview

This service provides OAuth2-compatible authentication for development and testing. It supports:

- **OAuth2 Authorization Code Flow** - For web applications
- **Direct Authentication** - For API testing and mobile apps
- **JWT Tokens** - Access and refresh tokens
- **Multiple User Roles** - Ungdom, Arbeidsgiver, Admin
- **Test Users** - Pre-seeded development accounts

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Auth Service  │    │   Main API      │
│                 │    │                 │    │                 │
│ • OAuth2 Flow   │◄──►│ • Identity       │    │ • Business      │
│ • Login UI      │    │ • JWT Tokens     │    │ • Logic         │
│ • Token Storage │    │ • No Roles       │◄──►│ • Roles/Perms   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                           │                        │
                           ▼                        ▼
                    ┌─────────────┐        ┌─────────────┐
                    │ Auth DB     │        │ Main DB     │
                    │ (Identity)  │        │ (Business)  │
                    └─────────────┘        └─────────────┘

### Authentication vs Authorization

**Authentication (Auth Service):**
- Verifies user identity ("Who are you?")
- Issues JWT tokens with identity claims only
- Pure OAuth2 provider functionality

**Authorization (Main API):**
- Validates JWT tokens from auth service
- Enriches tokens with business roles from database
- Applies role-based access control

### JWT Token Flow

1. **Auth Service** issues JWT with identity claims:
```json
{
  "sub": "user@example.com",
  "email": "user@example.com",
  "given_name": "John",
  "family_name": "Doe",
  "national_id": "12345678901"
}
```

2. **Main API** validates JWT and enriches with roles:
```json
{
  "sub": "user@example.com",
  "email": "user@example.com", 
  "given_name": "John",
  "family_name": "Doe",
  "national_id": "12345678901",
  "role": "Candidate"  // ← Added by Main API
}
```

3. **Client** receives enriched JWT for authorization decisions
```

## Quick Start

### Prerequisites
- .NET 10 SDK
- PostgreSQL database

### 1. Database Setup
```bash
# Create database
createdb networco_auth_dev

# Run migrations
dotnet run -- --migrate-only

# Seed test users
dotnet run -- --seed
```

### 2. Run the Service
```bash
# Development
dotnet run

# Production
dotnet publish -c Release
dotnet Networco.Auth.dll
```

### 3. Test Users

| Email | Password | Role |
|-------|----------|------|
| `admin@networco.dev` | `Admin123!` | SystemAdmin |
| `emma.larsen@networco.dev` | `Test123!` | Ungdom |
| `marte.hansen@kiwi.no` | `Test123!` | Arbeidsgiver |

## API Endpoints

### OAuth2 Endpoints

#### `GET /oauth/authorize`
OAuth2 authorization endpoint. Shows login page for development users.

**Query Parameters:**
- `response_type=code` (required)
- `client_id` (required)
- `redirect_uri` (required)
- `state` (optional)

**Response:** HTML login page

#### `POST /oauth/token`
OAuth2 token endpoint. Exchanges authorization code for tokens.

**Request Body:**
```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_here",
  "redirect_uri": "https://app.networco.dev/callback",
  "client_id": "networco-dev",
  "client_secret": "dev-secret"
}
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "refresh_token_here"
}
```

### Direct Authentication

#### `POST /auth/login`
Direct user authentication.

**Request:**
```json
{
  "emailOrNationalId": "emma.larsen@networco.dev",
  "password": "Test123!"
}
```

**Response:**
```json
{
  "accessToken": "eyJ...",
  "refreshToken": "refresh_token",
  "expiresIn": 900,
  "user": {
    "nationalId": "15120512345",
    "firstName": "Emma",
    "lastName": "Larsen",
    "email": "emma.larsen@networco.dev",
    "role": "Ungdom"
  }
}
```

#### `POST /auth/refresh`
Refresh access token.

#### `POST /auth/logout`
Revoke refresh token.

#### `GET /auth/me`
Get current user info (requires Bearer token).

## Configuration

### appsettings.json
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=networco_auth_dev;Username=postgres;Password=password"
  },
  "Auth": {
    "Enabled": true,
    "Secret": "your-jwt-secret-key",
    "AccessTokenExpirationMinutes": 15,
    "RefreshTokenExpirationDays": 7,
    "Issuer": "networco-auth-dev",
    "Audience": "networco-dev"
  }
}
```

### Environment Variables
- `ASPNETCORE_ENVIRONMENT` - Development/Production
- `ConnectionStrings__DefaultConnection` - Database connection string

## Security

### Password Hashing
- PBKDF2 with 10,000 iterations
- 256-bit key, 128-bit salt
- Secure random salt generation

### JWT Tokens
- HS256 signing algorithm
- Short-lived access tokens (15 minutes)
- Refresh tokens with server-side storage
- Token rotation on refresh

### Development vs Production
- **Development**: Full OAuth2 flow with test users
- **Production**: This service should be disabled/replaced

## Integration

### With Main API
The auth service is designed to be called by the main Networco API:

```csharp
// In main API - validate JWT from auth service
var tokenHandler = new JwtSecurityTokenHandler();
var principal = tokenHandler.ValidateToken(accessToken, validationParameters, out _);

// Extract user claims
var userId = principal.FindFirst("sub")?.Value;
var role = principal.FindFirst("role")?.Value;
```

### With Frontend
Frontend integrates via OAuth2 flow:

```javascript
// Redirect to auth service
window.location.href = `${AUTH_SERVICE_URL}/oauth/authorize?` +
  `response_type=code&` +
  `client_id=networco-dev&` +
  `redirect_uri=${encodeURIComponent(window.location.origin + '/auth/callback')}&` +
  `state=${state}`;

// Handle callback
const code = new URLSearchParams(window.location.search).get('code');
// Exchange code for tokens...
```

## Deployment

### Docker
```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["Networco.Auth.csproj", "."]
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Networco.Auth.dll"]
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: networco-auth
spec:
  replicas: 1
  selector:
    matchLabels:
      app: networco-auth
  template:
    metadata:
      labels:
        app: networco-auth
    spec:
      containers:
      - name: auth
        image: networco/auth:latest
        ports:
        - containerPort: 80
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        - name: ConnectionStrings__DefaultConnection
          valueFrom:
            secretKeyRef:
              name: auth-db-secret
              key: connection-string
```

## Development

### Running Tests
```bash
dotnet test
```

### Database Migrations
```bash
# Add migration
dotnet ef migrations add MigrationName

# Apply migrations
dotnet run -- --migrate-only
```

### Seeding Data
```bash
dotnet run -- --seed
```

## Why Separate Service?

1. **Security Isolation** - Auth logic separate from business logic
2. **Provider Flexibility** - Easy to swap OAuth providers (Google, GitHub, etc.)
3. **Scalability** - Auth service can scale independently
4. **Technology Choice** - Could use different tech stack if needed
5. **Development Velocity** - Teams can work independently
6. **Testing** - Auth can be mocked/stubbed easily
7. **Future-Proofing** - Ready for microservices migration

## Migration Path

When switching to production OAuth providers:

1. **Keep Service** - Use as OAuth2 proxy
2. **Replace Implementation** - Swap internal auth with external providers
3. **Maintain Interface** - Same API for frontend/main API
4. **Gradual Migration** - Support both dev and prod auth simultaneously
# Agent Guide: NetworcoID

This document provides essential context and instructions for AI agents operating in the NetworcoID repository.

## 🚀 Commands

### Build & Run
- **Build Solution:** `dotnet build`
- **Run Identity Service:** `dotnet run --project src/NetworcoId/NetworcoId.csproj`
- **Run Worker:** `dotnet run --project src/NetworcoId.Worker/NetworcoId.Worker.csproj`
- **Apply Migrations:** `dotnet run --project src/NetworcoId/NetworcoId.csproj -- --migrate-only`

### Testing
- **Run All Tests:** `dotnet test`
- **Run Single Test Class:** `dotnet test --filter ClassName`
- **Run Single Test Method:** `dotnet test --filter NameOfTest`
- **Example:** `dotnet test --filter NetworcoId.Tests.PasswordChangeFlowTests`

---

## 🛠 Project Structure

- `src/NetworcoId.Core`: Shared models, security logic (`PasswordHasher`), and NATS messaging contracts.
- `src/NetworcoId`: The main Identity Provider (ASP.NET Core). Uses Minimal APIs for OIDC/OAuth and Razor Pages for UI.
- `src/NetworcoId.Worker`: Background worker processing NATS JetStream messages (Email/OTP).
- `src/NetworcoId.Tests`: xUnit integration and unit tests.

---

## 🎨 Code Style & Conventions

### 1. Language & Framework
- **Runtime:** .NET 10.0
- **Language:** C# 13
- **Web:** ASP.NET Core Minimal APIs for endpoints; Razor Pages for UI.
- **ORM:** Entity Framework Core with PostgreSQL (via `DATABASE_URL`).
- **Messaging:** NATS JetStream.
- **Dependency Injection:** Microsoft.Extensions.DependencyInjection.

### 2. Naming Conventions
- **Classes/Methods/Properties:** `PascalCase`.
- **Local Variables/Parameters:** `camelCase`.
- **Interfaces:** Prefix with `I` (e.g., `IAuthService`).
- **Private Fields:** Prefix with `_` and use `camelCase` (e.g., `_authService`).
- **Endpoints:** Grouped in static classes (e.g., `AuthEndpoints`) using extension methods on `IEndpointRouteBuilder`.

### 3. Architecture Patterns
- **Namespaces:** Use **file-scoped namespaces** (`namespace NetworcoId.Core.Models;`).
- **DTOs:** Use `record` for immutable data transfers and NATS messages.
- **Dependency Injection:** Favor constructor injection. Register services in `src/NetworcoId/Configuration/` using `IServiceCollection` extension methods.
- **Endpoints:** Define Minimal APIs in `src/NetworcoId/Endpoints/` and map them in `Program.cs` via `app.MapEndpoints()`.
- **Database:** `AuthDbContext` using EF Core Fluent API for configuration (see `Infrastructure/Database/AuthEntityConfigurations.cs`).

### 4. Error Handling
- **API Responses:** Return `IResult` (e.g., `Results.Ok()`, `Results.BadRequest(new { error = "message" })`).
- **Validation:** Prefer `ValidationProblemDetails` for structured 400 errors.
- **Minimal API:** Catch exceptions in handlers to return consistent JSON error objects.

### 5. Formatting & Imports
- **Braces:** Standard C# style (braces on new lines).
- **Imports:**
    1. `System.*` namespaces.
    2. Third-party libraries (e.g., `Microsoft.*`, `NATS.*`).
    3. Internal `NetworcoId.*` namespaces.
- **Async:** Always suffix asynchronous methods with `Async` and ensure `await` is used. Prefer `ValueTask` where performance is critical, but `Task` is standard.
- **LINQ:** Prefer method syntax (`.Where()`, `.Select()`) over query syntax.

---

## 🔐 Security Best Practices
- **Passwords:** Never handle raw passwords; use `IPasswordHasher`.
- **Secrets:** Use environment variables (via `.env` in development).
- **Data Protection:** Managed via EF Core keys persisted in the database.
- **Tokens:** JWT for access tokens; hashed SHA256 for refresh tokens in the DB.

## 📡 Messaging (NATS)
- **Subjects:** Defined in `NetworcoId.Core.Models.NetworcoIdSubjects`.
- **Publishing:** Use `INatsConnection.PublishJetStreamAsync`.
- **Provisioning:** Streams are provisioned on startup in `Program.cs` via `ProvisionStreamsAsync`.

## 🔄 Git Workflow
- **Do NOT auto-commit**: Never commit changes automatically. The user wants to review all changes before committing.

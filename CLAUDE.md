# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`AGENTS.md` is the primary source for commands, conventions, and ground rules — read it. This file fills in the architectural picture that requires reading multiple files to understand.

## Solution layout

Four projects under `src/`:

- **`NetworcoId.Core`** — Shared library. Domain models, `PasswordHasher`, NATS subject constants (`NetworcoIdSubjects`), and `NatsExtensions` (stream provisioning helpers). No web/host dependencies.
- **`NetworcoId`** — The OIDC/OAuth identity provider (ASP.NET Core 10, Minimal APIs + Razor Pages). Owns the database schema and EF Core migrations.
- **`NetworcoId.Worker`** — Background worker. Consumes NATS JetStream messages (e.g. email, OTP) — does not serve HTTP.
- **`NetworcoId.Tests`** — xUnit. Split into `Integration/` and `Unit/`. Integration tests use the EF Core InMemory provider (see "Test mode" below).

## Request lifecycle (NetworcoId)

`Program.cs` is the canonical wiring. The flow:

1. **`.env` loading** — `DotNetEnv` walks up to three parents looking for `.env`. `clobberExistingVars: false` so CI/test env wins.
2. **Connection string resolution** — `DATABASE_URL` (Npgsql-style) takes precedence; otherwise assembled from `POSTGRES_HOST/PORT/DB/USER/PASSWORD`. The result is stuffed into `ConnectionStrings:DefaultConnection`.
3. **Service registration** — All `AddX` extension methods live in `src/NetworcoId/Configuration/` (`DatabaseConfiguration`, `NatsConfiguration`, `ServiceConfiguration`, `SettingsInitialLoader`). Add new wiring there, not inline in `Program.cs`.
4. **Data Protection** — Keys persist to `AuthDbContext` (so multiple instances share them). Optionally encrypted at rest with the cert at `DATA_PROTECTION_CERT_PATH`. The InMemory provider skips DB persistence.
5. **Migrate-only / seed shortcut** — `--migrate-only` or `--seed` runs migrations (and optionally `IAuthSeeder`) then exits before web wiring. Used by deploy jobs.
6. **Endpoint mapping** — `app.MapOAuth()`, `app.MapAuth()`, `app.MapAdmin()` (extension methods on `IEndpointRouteBuilder` defined in `src/NetworcoId/Endpoints/`). Razor Pages mapped alongside for the UI (login, register, account management).
7. **Startup-time bootstrap** — Inside a scope: retry-loop migrations (10×, 5s backoff), then `IBootstrapService.BootstrapAsync()` provisions the initial admin user and management OAuth client, then NATS streams are provisioned via `nats.ProvisionStreamsAsync(...)` (gated by `Nats:ProvisionStreams`).

## Rate limiting

Named policies registered in `Program.cs` and applied per-endpoint via `.RequireRateLimiting("name")`:

- `admin-login-strict` / `auth-login-strict` — Limits driven by `NetworcoIdConfig.AdminRateLimit*` / `AuthRateLimit*`.
- `auth-strict` — Hard 5/min cap for sensitive auth endpoints.

There is **no global limiter** — an endpoint without a policy attached is unlimited, so every new auth-adjacent endpoint must attach one explicitly. (A `fixed-ip` "global cap" existed as config but was never attached anywhere; it was removed rather than enabled, because on prod all client IPs currently collapse to the ingress gateway address and a global per-IP cap would throttle the whole user base at once.)

## Messaging boundary (NATS JetStream)

The Identity service **publishes** (e.g. user registered → send verification email); the Worker **subscribes** and does the side-effect work. Subjects are constants in `NetworcoId.Core.Models.NetworcoIdSubjects` — use them on both sides; never hardcode subject strings. Streams are provisioned at startup, so a new subject usually needs a corresponding entry in the provisioning helper.

## Test mode

Integration tests set the connection string to the literal `"InMemory"`. `Program.cs` and the data-protection wiring branch on this exact value to skip Postgres-only steps (DB key persistence, real migrations). Don't replace this string with empty/null checks — multiple call sites depend on the sentinel.

## Versioning & builds

- The `VERSION` file holds a four-part `major.minor.patch.build` number. `scripts/build.sh` bumps it on every build (the `build` segment increments unconditionally) and tags Docker images with both the full version and `latest`.
- Bump style is positional: `./scripts/build.sh patch|minor|major|<explicit-version>`; default is build-number-only. `--no-push` skips the registry push.
- Treat `VERSION` as build-managed — don't hand-edit unless coordinating a release.

## Conventions worth knowing up front

- **Endpoint files** group related routes as `IEndpointRouteBuilder` extension methods (one per area: OAuth, Auth, Admin). Don't add routes directly in `Program.cs`.
- **EF configuration** uses Fluent API in `Infrastructure/Database/AuthEntityConfigurations.cs`, not data annotations on the model classes.
- **Refresh tokens** are stored as SHA-256 hashes; the raw token only exists in the response. Don't add code that reads them back from the DB.
- **Do not auto-commit** — the user reviews diffs before every commit (per `AGENTS.md`).

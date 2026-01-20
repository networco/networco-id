using NetworcoId.Configuration;
using NetworcoId.Endpoints;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Services;
using NetworcoId.Services.System;
using Microsoft.EntityFrameworkCore;
using NATS.Client.Core;
using NetworcoId.Core;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Load environment variables if .env exists
// Note: We use NoOverwrite to ensure that if variables are already set (e.g. by CI or Tests), we don't clobber them.
if (File.Exists(".env"))
{
    DotNetEnv.Env.Load(".env", new DotNetEnv.LoadOptions(
        setEnvVars: true,
        clobberExistingVars: false,
        onlyExactPath: false
    ));
}
else if (File.Exists("../../.env"))
{
    DotNetEnv.Env.Load("../../.env", new DotNetEnv.LoadOptions(
        setEnvVars: true,
        clobberExistingVars: false,
        onlyExactPath: false
    ));
}
else if (File.Exists("../../../.env"))
{
    DotNetEnv.Env.Load("../../../.env", new DotNetEnv.LoadOptions(
        setEnvVars: true,
        clobberExistingVars: false,
        onlyExactPath: false
    ));
}

// Override configuration with environment variables
var dbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
if (string.IsNullOrEmpty(dbUrl))
{
    var pgHost = Environment.GetEnvironmentVariable("POSTGRES_HOST");
    var pgPort = Environment.GetEnvironmentVariable("POSTGRES_PORT") ?? "5432";
    var pgDb = Environment.GetEnvironmentVariable("POSTGRES_DB");
    var pgUser = Environment.GetEnvironmentVariable("POSTGRES_USER");
    var pgPass = Environment.GetEnvironmentVariable("POSTGRES_PASSWORD");

    if (!string.IsNullOrEmpty(pgHost) && !string.IsNullOrEmpty(pgDb) && !string.IsNullOrEmpty(pgUser))
    {
        dbUrl = $"Host={pgHost};Port={pgPort};Database={pgDb};Username={pgUser};Password={pgPass};Ssl Mode=Prefer;";
    }
}

if (!string.IsNullOrEmpty(dbUrl))
{
    builder.Configuration["ConnectionStrings:DefaultConnection"] = dbUrl;
}

var natsUrl = Environment.GetEnvironmentVariable("NATS_URL");
if (!string.IsNullOrEmpty(natsUrl))
{
    builder.Configuration["Nats:Url"] = natsUrl;
}

var migrateOnly = args.Contains("--migrate-only");
var seed = args.Contains("--seed");

// Configure core services
builder.Services.AddHttpContextAccessor();
builder.Services.AddJsonSerialization();
builder.Services.AddDatabase(builder.Configuration);
builder.Services.AddAuthServices(builder.Configuration);


// Configure Data Protection for multi-instance deployments
var dataProtectionBuilder = builder.Services.AddDataProtection()
    .SetApplicationName("NetworcoId");

// Only persist keys to DB if not using InMemory (tests)
var dbConnString = builder.Configuration.GetConnectionString("DefaultConnection");
if (dbConnString != "InMemory")
{
    dataProtectionBuilder.PersistKeysToDbContext<AuthDbContext>();
}

// If certificate path is configured, use it for encryption at rest
var certPath = builder.Configuration["DATA_PROTECTION_CERT_PATH"];
var certPass = builder.Configuration["DATA_PROTECTION_CERT_PASSWORD"];

if (!string.IsNullOrEmpty(certPath) && File.Exists(certPath))
{
#pragma warning disable SYSLIB0057 // Suppress obsolete warning for X509Certificate2 constructor
    var certificate = new X509Certificate2(certPath, certPass);
#pragma warning restore SYSLIB0057
    dataProtectionBuilder.ProtectKeysWithCertificate(certificate);
}


// Add NATS for messaging
builder.Services.AddNatsMessaging(builder.Configuration);

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

// If migrate-only or seed, handle and exit
if (migrateOnly || seed)
{
    var webApp = builder.Build();

    using var scope = webApp.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

    if (migrateOnly || seed)
    {
        Console.WriteLine("Running database migrations...");
        await db.Database.MigrateAsync();
        Console.WriteLine("Migrations completed successfully!");
    }

    if (seed)
    {
        var seeder = scope.ServiceProvider.GetRequiredService<IAuthSeeder>();
        await seeder.SeedAsync();
    }

    return;
}

// Normal web server mode - add all services
builder.Services.AddOpenApi();
builder.Services.AddRazorPages();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Global limit per IP
    options.AddPolicy("fixed-ip", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    // Strict limit for Auth endpoints
    options.AddPolicy("auth-strict", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

var app = builder.Build();

// Configure the HTTP request pipeline
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseRateLimiter();
app.UseCors();

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseStaticFiles();
app.UseRouting();

// Authentication & Authorization must be AFTER UseRouting and BEFORE UseEndpoints (in .NET 6+ Minimal APIs, mapped after)
app.UseAuthentication();
app.UseAuthorization();

// Map endpoints
app.MapRazorPages();
app.MapOAuth();
app.MapAuth();
app.MapAdmin();

// Health check
app.MapGet("/health", () => Results.Ok(new { status = "healthy", service = "auth" }))
    .WithName("Health")
    .WithTags("🏥 Health");

// Provision NATS streams on startup
using (var scope = app.Services.CreateScope())
{
    var connString = app.Configuration.GetConnectionString("DefaultConnection");
    // Only migrate if we are NOT using InMemory (which is used for tests)
    if (connString != "InMemory")
    {
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        // Double check provider to be safe
        if (db.Database.ProviderName != "Microsoft.EntityFrameworkCore.InMemory")
        {
            await db.Database.MigrateAsync();
        }
    }

    // Bootstrap system (Initial Admin and Management Client)
    var bootstrap = scope.ServiceProvider.GetRequiredService<IBootstrapService>();
    await bootstrap.BootstrapAsync();

    var config = scope.ServiceProvider.GetRequiredService<IConfiguration>();
    if (config.GetValue<bool>("Nats:ProvisionStreams", true))
    {
        var nats = scope.ServiceProvider.GetRequiredService<INatsConnection>();
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("NatsProvisioner");
        await nats.ProvisionStreamsAsync(logger);
    }
}

app.Run();

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

var builder = WebApplication.CreateBuilder(args);

// Load environment variables if .env exists
if (File.Exists(".env"))
{
    DotNetEnv.Env.Load(".env");
}
else if (File.Exists("../../.env"))
{
    // Try root from bin/Debug/net10.0
    DotNetEnv.Env.Load("../../.env");
}
else if (File.Exists("../../../.env"))
{
    // Try root from src/NetworcoId/bin/Debug/net10.0
    DotNetEnv.Env.Load("../../../.env");
}

// Override configuration with environment variables
var dbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
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
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<AuthDbContext>()
    .SetApplicationName("NetworcoId");

// Add NATS for messaging
builder.Services.AddNatsMessaging(builder.Configuration, "NetworcoId");

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
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    if (db.Database.ProviderName != "Microsoft.EntityFrameworkCore.InMemory")
    {
        await db.Database.MigrateAsync();
    }

    // Bootstrap system (Initial Admin and Management Client)
    var bootstrap = scope.ServiceProvider.GetRequiredService<IBootstrapService>();
    await bootstrap.BootstrapAsync();

    var nats = scope.ServiceProvider.GetRequiredService<INatsConnection>();
    var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("NatsProvisioner");
    await nats.ProvisionStreamsAsync(logger);
}

app.Run();

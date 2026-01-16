using Networco.Auth.Configuration;
using Networco.Auth.Endpoints;
using NetworcoId.Core.Security;
using Networco.Auth.Infrastructure.Database;
using Networco.Auth.Models.Auth;
using Networco.Auth.Services;
using Microsoft.EntityFrameworkCore;
using NATS.Client.Core;
using NetworcoId.Core;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

// Load environment variables if secrets.env exists
if (File.Exists("secrets.env"))
{
    DotNetEnv.Env.Load("secrets.env");
}

var migrateOnly = args.Contains("--migrate-only");
var seed = args.Contains("--seed");

// Configure core services
builder.Services.AddJsonSerialization();
builder.Services.AddDatabase(builder.Configuration);
builder.Services.AddAuthServices(builder.Configuration);

// Configure Data Protection for multi-instance deployments
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<AuthDbContext>()
    .SetApplicationName("Networco.Auth");

// Add NATS for messaging
builder.Services.AddNatsMessaging(builder.Configuration, "Networco.Auth");

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
    var nats = scope.ServiceProvider.GetRequiredService<INatsConnection>();
    var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("NatsProvisioner");
    await nats.ProvisionStreamsAsync(logger);
}

app.Run();

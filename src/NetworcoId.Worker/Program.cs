using NetworcoId.Core;
using NetworcoId.Worker;
using NetworcoId.Worker.Services;
using System.Net.Mail;

var builder = Host.CreateApplicationBuilder(args);

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
    // Try root from src/NetworcoId.Worker/bin/Debug/net10.0
    DotNetEnv.Env.Load("../../../.env");
}
else if (File.Exists("../../../../.env"))
{
    // Try root from deeper in the build tree
    DotNetEnv.Env.Load("../../../../.env");
}

// Map configuration
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
        dbUrl = $"Host={pgHost};Port={pgPort};Database={pgDb};Username={pgUser};Password={pgPass};Ssl Mode=Prefer;Trust Server Certificate=true;";
    }
}

builder.Configuration["ConnectionStrings:DefaultConnection"] = dbUrl;
builder.Configuration["Nats:Url"] = Environment.GetEnvironmentVariable("NATS_URL");

// Brevo Mapping - Ensure multiple possible env var names are covered
var brevoKey = Environment.GetEnvironmentVariable("BREVO_API_KEY") ?? Environment.GetEnvironmentVariable("BREVO_APIKEY");
builder.Configuration["Brevo:ApiKey"] = brevoKey;

var senderName = Environment.GetEnvironmentVariable("BREVO_SENDER_NAME");
if (!string.IsNullOrEmpty(senderName)) builder.Configuration["Brevo:SenderName"] = senderName;

var senderEmail = Environment.GetEnvironmentVariable("BREVO_SENDER_EMAIL");
if (!string.IsNullOrEmpty(senderEmail)) builder.Configuration["Brevo:SenderEmail"] = senderEmail;

if (string.IsNullOrEmpty(brevoKey))
{
    Console.WriteLine("CRITICAL WARNING: BREVO_API_KEY environment variable is null or empty!");
}
else
{
    Console.WriteLine($"Brevo API Key loaded (starts with: {brevoKey[..8]}...)");
}

builder.Services.AddNatsMessaging(builder.Configuration, "NetworcoId.Worker");

// Configure Brevo Email Service
builder.Services.Configure<BrevoSettings>(builder.Configuration.GetSection("Brevo"));
builder.Services.AddHttpClient<IBrevoEmailService, BrevoEmailService>();

// Add FluentEmail (keeping as secondary/local fallback if needed)
builder.Services
    .AddFluentEmail("no-reply@networco.no", "NetworcoID")
    .AddRazorRenderer()
    .AddSmtpSender(new SmtpClient("localhost", 1025)); 

builder.Services.AddHostedService<EmailWorker>();

var host = builder.Build();
host.Run();

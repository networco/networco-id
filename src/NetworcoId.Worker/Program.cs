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
builder.Configuration["ConnectionStrings:DefaultConnection"] = Environment.GetEnvironmentVariable("DATABASE_URL");
builder.Configuration["Nats:Url"] = Environment.GetEnvironmentVariable("NATS_URL");

// Brevo Mapping - Ensure multiple possible env var names are covered
var brevoKey = Environment.GetEnvironmentVariable("BREVO_API_KEY") ?? Environment.GetEnvironmentVariable("BREVO_APIKEY");
builder.Configuration["Brevo:ApiKey"] = brevoKey;
builder.Configuration["Brevo:SenderName"] = Environment.GetEnvironmentVariable("BREVO_SENDER_NAME");
builder.Configuration["Brevo:SenderEmail"] = Environment.GetEnvironmentVariable("BREVO_SENDER_EMAIL");

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

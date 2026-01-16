using NetworcoId.Core;
using NetworcoId.Worker;
using NetworcoId.Worker.Services;
using System.Net.Mail;

var builder = Host.CreateApplicationBuilder(args);

// Load environment variables from .env file
var envPath = Path.Combine(AppContext.BaseDirectory, "../../../.env");
if (File.Exists(envPath))
{
    DotNetEnv.Env.Load(envPath);
}
else if (File.Exists(".env"))
{
    DotNetEnv.Env.Load(".env");
}

// Override configuration with environment variables
builder.Configuration["ConnectionStrings:DefaultConnection"] = Environment.GetEnvironmentVariable("DATABASE_URL");
builder.Configuration["Nats:Url"] = Environment.GetEnvironmentVariable("NATS_URL");
builder.Configuration["Brevo:ApiKey"] = Environment.GetEnvironmentVariable("BREVO_API_KEY");
builder.Configuration["Brevo:SenderName"] = Environment.GetEnvironmentVariable("BREVO_SENDER_NAME");
builder.Configuration["Brevo:SenderEmail"] = Environment.GetEnvironmentVariable("BREVO_SENDER_EMAIL");

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

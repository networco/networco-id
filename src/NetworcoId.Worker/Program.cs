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

var senderName = Environment.GetEnvironmentVariable("EMAIL_SENDER_NAME");
if (!string.IsNullOrEmpty(senderName)) builder.Configuration["Brevo:SenderName"] = senderName;

var senderEmail = Environment.GetEnvironmentVariable("EMAIL_SENDER_EMAIL");
if (!string.IsNullOrEmpty(senderEmail)) builder.Configuration["Brevo:SenderEmail"] = senderEmail;

// Resend mapping (optional second provider for failover). Sender defaults to
// the Brevo sender identity unless overridden — the sender domain must be
// verified in BOTH providers for failover to actually deliver.
var resendKey = Environment.GetEnvironmentVariable("RESEND_API_KEY");
if (!string.IsNullOrEmpty(resendKey)) builder.Configuration["Resend:ApiKey"] = resendKey;

var resendSenderName = Environment.GetEnvironmentVariable("RESEND_SENDER_NAME") ?? senderName;
if (!string.IsNullOrEmpty(resendSenderName)) builder.Configuration["Resend:SenderName"] = resendSenderName;

var resendSenderEmail = Environment.GetEnvironmentVariable("RESEND_SENDER_EMAIL") ?? senderEmail;
if (!string.IsNullOrEmpty(resendSenderEmail)) builder.Configuration["Resend:SenderEmail"] = resendSenderEmail;

// postbud mapping (the platform's own mail service, reached over the tailnet).
// Its sender identity is deliberately separate from Brevo's: postbud only
// accepts a From within the domains its tenant is registered for, so reusing
// the Brevo sender would be refused at the API rather than delivered.
var postbudUrl = Environment.GetEnvironmentVariable("POSTBUD_URL");
if (!string.IsNullOrEmpty(postbudUrl)) builder.Configuration["Postbud:Url"] = postbudUrl;

var postbudKey = Environment.GetEnvironmentVariable("POSTBUD_APIKEY");
if (!string.IsNullOrEmpty(postbudKey)) builder.Configuration["Postbud:ApiKey"] = postbudKey;

var postbudSenderName = Environment.GetEnvironmentVariable("POSTBUD_SENDER_NAME") ?? senderName;
if (!string.IsNullOrEmpty(postbudSenderName)) builder.Configuration["Postbud:SenderName"] = postbudSenderName;

var postbudSenderEmail = Environment.GetEnvironmentVariable("POSTBUD_SENDER_EMAIL");
if (!string.IsNullOrEmpty(postbudSenderEmail)) builder.Configuration["Postbud:SenderEmail"] = postbudSenderEmail;

if (string.IsNullOrEmpty(brevoKey))
{
    Console.WriteLine("CRITICAL WARNING: BREVO_API_KEY environment variable is null or empty!");
}
else
{
    Console.WriteLine($"Brevo API Key loaded (starts with: {brevoKey[..8]}...)");
}

builder.Services.AddNatsMessaging(builder.Configuration, "NetworcoId.Worker");

// Configure email providers + failover chain. EMAIL_PROVIDERS (comma-separated,
// ordered) selects providers and their failover order; defaults to "brevo" so
// the prior single-provider behaviour is unchanged. A provider is only included
// when its API key is set, so leaving RESEND_API_KEY empty yields Brevo-only.
builder.Services.Configure<BrevoSettings>(builder.Configuration.GetSection("Brevo"));
builder.Services.Configure<ResendSettings>(builder.Configuration.GetSection("Resend"));
builder.Services.Configure<PostbudSettings>(builder.Configuration.GetSection("Postbud"));
builder.Services.AddHttpClient<BrevoEmailService>();
builder.Services.AddHttpClient<ResendEmailService>();
builder.Services.AddHttpClient<PostbudEmailService>();

var emailProviders = (Environment.GetEnvironmentVariable("EMAIL_PROVIDERS") ?? "brevo")
    .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

builder.Services.AddSingleton<IEmailSender>(sp =>
{
    var senders = new List<IEmailSender>();
    foreach (var p in emailProviders)
    {
        switch (p.ToLowerInvariant())
        {
            case "brevo":
                if (!string.IsNullOrEmpty(brevoKey)) senders.Add(sp.GetRequiredService<BrevoEmailService>());
                break;
            case "resend":
                if (!string.IsNullOrEmpty(resendKey)) senders.Add(sp.GetRequiredService<ResendEmailService>());
                break;
            case "postbud":
                // Both the key AND the sender address, because postbud
                // refuses a From outside its tenant's domains: a chain that
                // silently included a provider guaranteed to be rejected
                // would just fail over on every send.
                if (!string.IsNullOrEmpty(postbudKey) && !string.IsNullOrEmpty(postbudSenderEmail))
                {
                    senders.Add(sp.GetRequiredService<PostbudEmailService>());
                }
                break;
        }
    }

    var logger = sp.GetRequiredService<ILogger<FailoverEmailService>>();
    if (senders.Count == 0)
    {
        logger.LogError("No email providers configured (BREVO_API_KEY / RESEND_API_KEY) — sends will fail");
        return sp.GetRequiredService<BrevoEmailService>(); // throws a clear 'key missing' error on send
    }
    if (senders.Count == 1)
    {
        logger.LogInformation("Email provider configured: {Provider}", senders[0].ProviderName);
        return senders[0];
    }
    logger.LogInformation("Email failover chain configured: {Order}", string.Join(",", senders.Select(s => s.ProviderName)));
    return new FailoverEmailService(senders, logger);
});

// Add FluentEmail (keeping as secondary/local fallback if needed)
builder.Services
    .AddFluentEmail("no-reply@networco.no", "NetworcoID")
    .AddRazorRenderer()
    .AddSmtpSender(new SmtpClient("localhost", 1025)); 

builder.Services.AddHostedService<EmailWorker>();

var host = builder.Build();
host.Run();

using NetworcoId.Core;
using NetworcoId.Worker;
using System.Net.Mail;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddNatsMessaging(builder.Configuration, "NetworcoId.Worker");

// Add FluentEmail
builder.Services
    .AddFluentEmail("no-reply@networco.no", "NetworcoID")
    .AddRazorRenderer()
    .AddSmtpSender(new SmtpClient("localhost", 1025)); // Default for MailHog/Mailpit in dev

builder.Services.AddHostedService<EmailWorker>();

var host = builder.Build();
host.Run();

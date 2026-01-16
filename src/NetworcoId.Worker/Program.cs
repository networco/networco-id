using NetworcoId.Core;
using NetworcoId.Worker;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddNatsMessaging(builder.Configuration, "NetworcoId.Worker");
builder.Services.AddHostedService<EmailWorker>();

var host = builder.Build();
host.Run();

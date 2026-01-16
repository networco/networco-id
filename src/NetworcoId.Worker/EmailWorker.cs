using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NetworcoId.Core;
using NetworcoId.Core.Models;
using NetworcoId.Worker.Services;

namespace NetworcoId.Worker;

public class EmailWorker(
    INatsConnection nats,
    IBrevoEmailService brevoEmail,
    ILogger<EmailWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("NetworcoID Email Worker starting...");

        var js = new NatsJSContext(nats);

        // Ensure stream exists
        await nats.ProvisionStreamsAsync(logger);

        var consumerName = "email-worker";

        // To handle WorkQueue streams reliably:
        // 1. We use a single durable consumer for the worker.
        // 2. This consumer handles ALL subjects on the NETWORCOID_IDENTITY stream.
        // 3. Since it's a WorkQueue, multiple instances of this worker will automatically
        //    load-balance messages by attaching to the same durable consumer.
        INatsJSConsumer consumer;
        logger.LogInformation("Ensuring durable consumer: {Name} on stream {Stream}", consumerName, NetworcoIdSubjects.StreamName);
        
        consumer = await js.CreateOrUpdateConsumerAsync(NetworcoIdSubjects.StreamName, new ConsumerConfig
        {
            Name = consumerName,
            DurableName = consumerName,
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            DeliverPolicy = ConsumerConfigDeliverPolicy.All,
            AckWait = TimeSpan.FromSeconds(30),
            MaxDeliver = 3
        }, stoppingToken);

        logger.LogInformation("Consumer {Name} active and ready.", consumerName);

        logger.LogInformation("Consumer {Name} active. Listening for identity.email.>", consumerName);

        await foreach (var msg in consumer.ConsumeAsync<byte[]>(cancellationToken: stoppingToken))
        {
            try
            {
                var subject = msg.Subject;
                logger.LogInformation(">>> RECEIVED MESSAGE: {Subject}", subject);

                if (msg.Data == null || msg.Data.Length == 0)
                {
                    logger.LogWarning("Received empty message data on subject {Subject}", subject);
                    await msg.AckAsync(cancellationToken: stoppingToken);
                    continue;
                }

                // For messages published via NatsEmailService, they go to 'identity.email.notification'
                if (subject == NetworcoIdSubjects.EmailNotification)
                {
                    var data = System.Text.Json.JsonSerializer.Deserialize<EmailNotificationMessage>(msg.Data);
                    if (data != null)
                    {
                        logger.LogInformation("Processing EmailNotification for {Email}: {Subject}", data.Email, data.Subject);
                        await HandleNotificationEmail(data, stoppingToken);
                    }
                }
                else if (subject == NetworcoIdSubjects.EmailVerify)
                {
                    var data = System.Text.Json.JsonSerializer.Deserialize<EmailVerificationMessage>(msg.Data);
                    if (data != null) await HandleVerificationEmail(data, stoppingToken);
                }
                else if (subject == NetworcoIdSubjects.PasswordReset)
                {
                    var data = System.Text.Json.JsonSerializer.Deserialize<PasswordResetMessage>(msg.Data);
                    if (data != null) await HandlePasswordResetEmail(data, stoppingToken);
                }
                else
                {
                    logger.LogWarning("Received message on unhandled subject: {Subject}", subject);
                }

                await msg.AckAsync(cancellationToken: stoppingToken);
            }
            catch (System.Text.Json.JsonException jsonEx)
            {
                var dataStr = msg.Data != null ? System.Text.Encoding.UTF8.GetString(msg.Data) : "NULL";
                logger.LogError(jsonEx, "JSON Deserialization failed for message on {Subject}. Data: {Data}", 
                    msg.Subject, dataStr);
                // Ack bad messages to remove them from the WorkQueue so they don't block
                await msg.AckAsync(cancellationToken: stoppingToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to process message on subject {Subject}", msg.Subject);
            }
        }
    }

    private async Task HandleVerificationEmail(EmailVerificationMessage data, CancellationToken ct)
    {
        var subject = data.Type == "OTP" ? "Your NetworcoID Login Code" : "Verify your NetworcoID account";
        var body = data.Type == "OTP"
            ? $"Your login code is: {data.Token}"
            : $"Please verify your account using this token: {data.Token}\n\nLink: https://id.networco.no/verify?token={data.Token}";

        await brevoEmail.SendEmailAsync(data.Email, data.FirstName, subject, ToHtml(body), ct);
    }

    private async Task HandlePasswordResetEmail(PasswordResetMessage data, CancellationToken ct)
    {
        var body = $"You requested a password reset. Please use the following link to reset your password:\n\nLink: https://id.networco.no/Auth/ResetPassword?token={data.Token}\n\nThis link expires in 2 hours.";
        await brevoEmail.SendEmailAsync(data.Email, data.FirstName, "Reset your NetworcoID password", ToHtml(body), ct);
    }

    private async Task HandleNotificationEmail(EmailNotificationMessage data, CancellationToken ct)
    {
        await brevoEmail.SendEmailAsync(data.Email, data.FirstName ?? data.Email, data.Subject, ToHtml(data.Body), ct);
    }

    private string ToHtml(string text) => $"<html><body><p>{text.Replace("\n", "<br>")}</p></body></html>";
}

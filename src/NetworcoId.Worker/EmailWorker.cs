using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NetworcoId.Core;
using NetworcoId.Core.Models;

namespace NetworcoId.Worker;

public class EmailWorker(
    INatsConnection nats,
    ILogger<EmailWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("NetworcoID Email Worker starting...");

        var js = new NatsJSContext(nats);
        
        // Ensure stream exists
        await nats.ProvisionStreamsAsync(logger);

        // Standard JetStream consumer pattern
        var consumer = await js.CreateOrUpdateConsumerAsync(NetworcoIdSubjects.StreamName, new ConsumerConfig("email-worker")
        {
            FilterSubject = NetworcoIdSubjects.EmailVerify,
            DurableName = "email-worker",
            AckPolicy = ConsumerConfigAckPolicy.Explicit
        }, stoppingToken);

        await foreach (var msg in consumer.ConsumeAsync<EmailVerificationMessage>(cancellationToken: stoppingToken))
        {
            var emailMsg = msg.Data;
            if (emailMsg == null) continue;

            logger.LogInformation("Processing email for {Email} (Type: {Type})", emailMsg.Email, emailMsg.Type);
            
            try 
            {
                if (emailMsg.Type == "Verification")
                {
                    logger.LogInformation("Sending verification email to {Email} with token {Token}", emailMsg.Email, emailMsg.Token);
                    // TODO: Implement actual SMTP/SendGrid call
                }
                else if (emailMsg.Type == "OTP")
                {
                    logger.LogInformation("Sending OTP code to {Email}", emailMsg.Email);
                    // TODO: Implement actual SMTP/SendGrid call
                }

                await msg.AckAsync(cancellationToken: stoppingToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to process email for {Email}", emailMsg.Email);
                // NATS will retry based on AckWait if we don't Ack
            }
        }
    }
}

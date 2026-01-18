using NATS.Client.Core;
using NetworcoId.Core.Models;

namespace NetworcoId.Services.Messaging;

/// <summary>
/// Email service interface for sending notifications.
/// </summary>
public interface IEmailService
{
    Task SendEmailAsync(string to, string subject, string body, string? firstName = null);
}

/// <summary>
/// NATS-based email service that publishes messages to a queue for processing by a worker.
/// </summary>
public class NatsEmailService(INatsConnection nats, ILogger<NatsEmailService> logger) : IEmailService
{
    public async Task SendEmailAsync(string to, string subject, string body, string? firstName = null)
    {
        var message = new EmailNotificationMessage(to, subject, body, firstName);
        var jsonBytes = global::System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(message);
        
        try
        {
            await nats.PublishAsync(NetworcoIdSubjects.EmailNotification, jsonBytes);
            logger.LogInformation("Published email notification to NATS: {To} - {Subject}", to, subject);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to publish email notification to NATS");
            // In a real system, you might want to retry or fallback to a secondary method
        }
    }
}


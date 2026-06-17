namespace NetworcoId.Worker.Services;

/// <summary>
/// Provider-agnostic transactional email sender. <see cref="ProviderName"/> is
/// used for failover and observability logging. Implementations: Brevo, Resend,
/// and the composing <see cref="FailoverEmailService"/>.
/// </summary>
public interface IEmailSender
{
    string ProviderName { get; }

    Task SendEmailAsync(string toEmail, string toName, string subject, string htmlContent, string? textContent = null, CancellationToken ct = default);
}

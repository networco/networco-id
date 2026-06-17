namespace NetworcoId.Worker.Services;

/// <summary>
/// Tries an ordered list of providers, returning on the first success. Only
/// throws (so the NATS consumer redelivers) when EVERY provider fails — keeping
/// must-deliver auth mail resilient to a single provider's outage or rate limit.
/// </summary>
public class FailoverEmailService : IEmailSender
{
    private readonly IReadOnlyList<IEmailSender> _senders;
    private readonly ILogger<FailoverEmailService> _logger;

    public FailoverEmailService(IReadOnlyList<IEmailSender> senders, ILogger<FailoverEmailService> logger)
    {
        _senders = senders;
        _logger = logger;
    }

    public string ProviderName => "failover";

    public async Task SendEmailAsync(string toEmail, string toName, string subject, string htmlContent, string? textContent = null, CancellationToken ct = default)
    {
        var errors = new List<Exception>();
        for (var i = 0; i < _senders.Count; i++)
        {
            var sender = _senders[i];
            try
            {
                await sender.SendEmailAsync(toEmail, toName, subject, htmlContent, textContent, ct);
                if (i > 0)
                {
                    _logger.LogWarning("Email delivered via fallback provider {Provider} after {Failed} failure(s)", sender.ProviderName, i);
                }
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Email provider {Provider} failed, trying next", sender.ProviderName);
                errors.Add(ex);
            }
        }

        throw new AggregateException("All email providers failed", errors);
    }
}

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace NetworcoId.Worker.Services;

public class PostbudSettings
{
    public string Url { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;
    public string SenderName { get; set; } = "NETWORCO";
    public string SenderEmail { get; set; } = string.Empty;
}

/// <summary>
/// Sends through postbud, the platform's own outbound mail service.
///
/// Unlike Brevo and Resend this is not a hosted provider: postbud owns the
/// queue, the suppression list and the delivery record, and a Postfix relay
/// behind it owns delivery and DKIM signing. Nothing here retries, because
/// postbud persists a message on accept and retries it for roughly two days
/// — which is precisely why it belongs FIRST in the failover chain rather
/// than last. Falling through to another provider would mean two systems
/// writing to the same address with two different suppression lists.
/// </summary>
public partial class PostbudEmailService : IEmailSender
{
    public string ProviderName => "postbud";

    private readonly HttpClient _httpClient;
    private readonly PostbudSettings _settings;
    private readonly ILogger<PostbudEmailService> _logger;

    public PostbudEmailService(
        HttpClient httpClient,
        IOptions<PostbudSettings> settings,
        ILogger<PostbudEmailService> logger)
    {
        _httpClient = httpClient;
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task SendEmailAsync(
        string toEmail,
        string toName,
        string subject,
        string htmlContent,
        string? textContent = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_settings.Url) ||
            string.IsNullOrWhiteSpace(_settings.ApiKey) ||
            string.IsNullOrWhiteSpace(_settings.SenderEmail))
        {
            // Loud rather than silent. A mail path that quietly drops
            // messages when misconfigured is worse than one that fails:
            // nobody finds out until a user asks why the reset link never
            // arrived.
            _logger.LogError("Postbud is not configured (URL, API key and sender address are all required)");
            throw new InvalidOperationException("Postbud is not configured");
        }

        // The configured sender is either a bare address or "Name <addr>".
        // The deploy's env file uses the latter -- and postbud takes `from`
        // as an ADDRESS, so passing the whole string through would send the
        // display name as part of the address and be refused.
        var (fromName, fromEmail) = NetworcoId.Core.SenderAddress.Split(
            _settings.SenderEmail, _settings.SenderName);

        var payload = new
        {
            // No stable business id reaches this layer, so a NATS
            // redelivery would be a second mail. Bounded rather than
            // unbounded: the worker's consumer acks after send and caps at
            // MaxDeliver=3. Giving the queued events their own ids is the
            // proper fix and is tracked separately.
            idempotency_key = Guid.NewGuid().ToString(),
            from = fromEmail,
            from_name = fromName,
            to = toEmail,
            subject,
            // postbud wants at least one body. HTML-only mail scores worse
            // at every large receiver, so derive a plain part when the
            // caller did not supply one -- crude by construction, it exists
            // for deliverability and not as a faithful rendering.
            text = string.IsNullOrWhiteSpace(textContent) ? ToPlainText(htmlContent) : textContent,
            html = htmlContent,
        };

        var url = $"{_settings.Url.TrimEnd('/')}/v1/messages";
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _settings.ApiKey);
        request.Content = JsonContent.Create(payload);

        _logger.LogInformation("Attempting to send email to {Email} with subject '{Subject}' using postbud", toEmail, subject);

        var response = await _httpClient.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(ct);
            _logger.LogError("Failed to send email via postbud. Status: {Status}, Error: {Error}", response.StatusCode, error);
            throw new Exception($"postbud API error: {response.StatusCode}");
        }

        _logger.LogInformation("Email accepted by postbud for {Email}", toEmail);
    }

    private static string ToPlainText(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        // Block boundaries become newlines before the tags go, so the
        // result keeps some shape instead of collapsing into one paragraph.
        var text = BreakTags().Replace(html, "\n");
        text = AllTags().Replace(text, string.Empty);
        text = System.Net.WebUtility.HtmlDecode(text);
        text = ExcessBlankLines().Replace(text, "\n\n");
        return text.Trim();
    }

    [GeneratedRegex(@"<\s*(br|/p|/div|/li|/h[1-6]|/tr)\s*/?\s*>", RegexOptions.IgnoreCase)]
    private static partial Regex BreakTags();

    [GeneratedRegex(@"<[^>]+>")]
    private static partial Regex AllTags();

    [GeneratedRegex(@"\n{3,}")]
    private static partial Regex ExcessBlankLines();
}

using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace NetworcoId.Worker.Services;

public class ResendSettings
{
    public string ApiKey { get; set; } = "";
    public string SenderName { get; set; } = "NETWORCO";
    public string SenderEmail { get; set; } = "noreply@networco.no";
}

public class ResendEmailService : IEmailSender
{
    private static readonly System.Text.Json.JsonSerializerOptions NullIgnoringJsonOptions = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _httpClient;
    private readonly ResendSettings _settings;
    private readonly ILogger<ResendEmailService> _logger;

    public ResendEmailService(
        HttpClient httpClient,
        IOptions<ResendSettings> settings,
        ILogger<ResendEmailService> logger)
    {
        _httpClient = httpClient;
        _settings = settings.Value;
        _logger = logger;
    }

    public string ProviderName => "resend";

    public async Task SendEmailAsync(string toEmail, string toName, string subject, string htmlContent, string? textContent = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_settings.ApiKey))
        {
            _logger.LogError("Resend API Key is missing in configuration");
            throw new InvalidOperationException("Resend API Key is missing");
        }

        // Resend takes a single "from" string and a list of "to" addresses, each
        // in "Name <email>" form — unlike Brevo's structured sender/to objects.
        var from = string.IsNullOrEmpty(_settings.SenderName)
            ? _settings.SenderEmail
            : $"{_settings.SenderName} <{_settings.SenderEmail}>";
        var to = string.IsNullOrEmpty(toName) ? toEmail : $"{toName} <{toEmail}>";

        var requestBody = new
        {
            from,
            to = new[] { to },
            subject,
            html = htmlContent,
            text = string.IsNullOrWhiteSpace(textContent) ? null : textContent,
        };

        try
        {
            _logger.LogInformation("Attempting to send email to {Email} with subject '{Subject}' using Resend", toEmail, subject);

            using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.resend.com/emails");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _settings.ApiKey);
            request.Content = JsonContent.Create(requestBody, options: NullIgnoringJsonOptions);

            var response = await _httpClient.SendAsync(request, ct);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync(ct);
                _logger.LogError("Failed to send email via Resend. Status: {Status}, Error: {Error}",
                    response.StatusCode, error);
                throw new Exception($"Resend API error: {response.StatusCode}");
            }

            _logger.LogInformation("Email sent successfully to {Email} via Resend", toEmail);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while sending email to {Email} via Resend", toEmail);
            throw;
        }
    }
}

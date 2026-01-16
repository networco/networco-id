using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace NetworcoId.Worker.Services;

public class BrevoSettings
{
    public required string ApiKey { get; set; }
    public string SenderName { get; set; } = "NETWORCO";
    public string SenderEmail { get; set; } = "networco@bogentech.no";
}

public interface IBrevoEmailService
{
    Task SendEmailAsync(string toEmail, string toName, string subject, string htmlContent, CancellationToken ct = default);
}

public class BrevoEmailService : IBrevoEmailService
{
    private readonly HttpClient _httpClient;
    private readonly BrevoSettings _settings;
    private readonly ILogger<BrevoEmailService> _logger;

    public BrevoEmailService(
        HttpClient httpClient,
        IOptions<BrevoSettings> settings,
        ILogger<BrevoEmailService> logger)
    {
        _httpClient = httpClient;
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task SendEmailAsync(string toEmail, string toName, string subject, string htmlContent, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_settings.ApiKey))
        {
            _logger.LogError("Brevo API Key is missing in configuration");
            throw new InvalidOperationException("Brevo API Key is missing");
        }

        var requestBody = new
        {
            sender = new { name = _settings.SenderName, email = _settings.SenderEmail },
            to = new[] { new { email = toEmail, name = toName } },
            subject = subject,
            htmlContent = htmlContent
        };

        try
        {
            _logger.LogInformation("Attempting to send email to {Email} with subject '{Subject}' using Brevo", toEmail, subject);

            using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.brevo.com/v3/smtp/email");
            request.Headers.TryAddWithoutValidation("api-key", _settings.ApiKey);
            request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            request.Content = JsonContent.Create(requestBody);

            var response = await _httpClient.SendAsync(request, ct);
            
            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync(ct);
                _logger.LogError("Failed to send email via Brevo. Status: {Status}, Error: {Error}", 
                    response.StatusCode, error);
                throw new Exception($"Brevo API error: {response.StatusCode}");
            }

            _logger.LogInformation("Email sent successfully to {Email} via Brevo", toEmail);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while sending email to {Email}", toEmail);
            throw;
        }
    }
}

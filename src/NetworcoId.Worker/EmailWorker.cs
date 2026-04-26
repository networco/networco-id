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
    private const string ConsumerName = "email-worker";
    private static readonly TimeSpan ReconnectDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMinutes(1);

    private long _processedSinceHeartbeat;
    private DateTimeOffset _lastActivityAt = DateTimeOffset.UtcNow;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("NetworcoID Email Worker starting...");

        // Background heartbeat so we can SEE the worker is alive even when no
        // mail traffic is flowing. Without this, an idle period is
        // indistinguishable from a stuck consumer.
        _ = Task.Run(() => HeartbeatAsync(stoppingToken), stoppingToken);

        // Outer loop: if the consume pump exits for ANY reason (stream
        // disconnect, transient NATS error, or — most importantly — the
        // ConsumeAsync enumerator silently completing), log loudly and
        // reconnect rather than sitting silently. Previously the foreach
        // could exit without exception and the worker would idle forever
        // with K8s still reporting the pod as Ready.
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunConsumeLoopAsync(stoppingToken);

                // ConsumeAsync should only complete on cancellation. If we get
                // here without cancellation, the stream/consumer ended on us.
                if (!stoppingToken.IsCancellationRequested)
                {
                    logger.LogError("Consume loop exited unexpectedly without cancellation. Reconnecting in {Delay}s...", ReconnectDelay.TotalSeconds);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                logger.LogInformation("Worker shutdown requested");
                return;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Consume loop crashed. Reconnecting in {Delay}s...", ReconnectDelay.TotalSeconds);
            }

            try
            {
                await Task.Delay(ReconnectDelay, stoppingToken);
            }
            catch (OperationCanceledException) { return; }
        }
    }

    private async Task RunConsumeLoopAsync(CancellationToken stoppingToken)
    {
        var js = new NatsJSContext(nats);

        // Ensure stream exists
        await nats.ProvisionStreamsAsync(logger);

        // To handle WorkQueue streams reliably:
        // 1. We use a single durable consumer for the worker.
        // 2. This consumer handles ALL subjects on the NETWORCOID_IDENTITY stream.
        // 3. Since it's a WorkQueue, multiple instances of this worker will automatically
        //    load-balance messages by attaching to the same durable consumer.
        logger.LogInformation("Ensuring durable consumer: {Name} on stream {Stream}", ConsumerName, NetworcoIdSubjects.StreamName);

        var consumer = await js.CreateOrUpdateConsumerAsync(NetworcoIdSubjects.StreamName, new ConsumerConfig
        {
            Name = ConsumerName,
            DurableName = ConsumerName,
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            DeliverPolicy = ConsumerConfigDeliverPolicy.All,
            AckWait = TimeSpan.FromSeconds(30),
            MaxDeliver = 3,
        }, stoppingToken);

        logger.LogInformation("Consumer {Name} active. Listening for identity.email.>", ConsumerName);
        _lastActivityAt = DateTimeOffset.UtcNow;

        await foreach (var msg in consumer.ConsumeAsync<byte[]>(cancellationToken: stoppingToken))
        {
            _lastActivityAt = DateTimeOffset.UtcNow;
            await ProcessMessageAsync(msg, stoppingToken);
            Interlocked.Increment(ref _processedSinceHeartbeat);
        }
    }

    private async Task ProcessMessageAsync(INatsJSMsg<byte[]> msg, CancellationToken stoppingToken)
    {
        try
        {
            var subject = msg.Subject;
            logger.LogInformation(">>> RECEIVED MESSAGE: {Subject}", subject);

            if (msg.Data == null || msg.Data.Length == 0)
            {
                logger.LogWarning("Received empty message data on subject {Subject}", subject);
                await msg.AckAsync(cancellationToken: stoppingToken);
                return;
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
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutdown — don't ack so the message will be redelivered after restart.
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to process message on subject {Subject}. Will be retried (MaxDeliver=3).", msg.Subject);
            // Don't ack — let NATS redeliver per the consumer config.
        }
    }

    private async Task HeartbeatAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(HeartbeatInterval, stoppingToken);
            }
            catch (OperationCanceledException) { return; }

            var processed = Interlocked.Exchange(ref _processedSinceHeartbeat, 0);
            var idleFor = DateTimeOffset.UtcNow - _lastActivityAt;
            logger.LogInformation(
                "EmailWorker heartbeat: processed {Count} message(s) in last {Interval}s; last activity {IdleSeconds:F0}s ago",
                processed, HeartbeatInterval.TotalSeconds, idleFor.TotalSeconds);
        }
    }

    private async Task HandleVerificationEmail(EmailVerificationMessage data, CancellationToken ct)
    {
        var firstName = string.IsNullOrWhiteSpace(data.FirstName) ? null : data.FirstName;
        var greeting = firstName is null ? "Hei!" : $"Hei {firstName},";

        EmailTemplateModel model;
        string subject;

        if (data.Type == "OTP")
        {
            subject = "Din NETWORCO innloggingskode";
            model = new EmailTemplateModel(
                Heading: "Din innloggingskode",
                Greeting: greeting,
                IntroParagraph: $"Bruk koden under for å logge inn: {data.Token}",
                FinePrintParagraph: "Koden er gyldig i kort tid. Hvis du ikke prøvde å logge inn, kan du trygt ignorere denne meldingen.");
        }
        else
        {
            var baseUrl = data.BaseUrl?.TrimEnd('/') ?? "https://id.networco.no";
            var verifyUrl = $"{baseUrl}/verify?token={data.Token}";
            subject = "Bekreft NETWORCO-kontoen din";
            model = new EmailTemplateModel(
                Heading: "Bekreft e-postadressen din",
                Greeting: greeting,
                IntroParagraph: "Takk for at du registrerte deg på NETWORCO! Klikk på knappen under for å bekrefte e-postadressen din og fullføre registreringen.",
                CtaUrl: verifyUrl,
                CtaLabel: "Bekreft e-postadressen min",
                FinePrintParagraph: "Lenken er gyldig i 30 minutter og kan kun brukes én gang. Hvis du ikke registrerte deg på NETWORCO, kan du trygt slette denne e-posten.");
        }

        await brevoEmail.SendEmailAsync(
            data.Email,
            data.FirstName,
            subject,
            EmailTemplate.ToHtml(model),
            EmailTemplate.ToText(model),
            ct);
    }

    private async Task HandlePasswordResetEmail(PasswordResetMessage data, CancellationToken ct)
    {
        var baseUrl = data.BaseUrl?.TrimEnd('/') ?? "https://id.networco.no";
        var resetUrl = $"{baseUrl}/Auth/ResetPassword?token={data.Token}";
        // Carry the originating /Login URL through the reset flow so that
        // after a successful password change the "Logg inn" button drops the
        // user back into the OAuth handshake they started, instead of a
        // bare /Login page.
        if (!string.IsNullOrWhiteSpace(data.ReturnUrl))
        {
            resetUrl += $"&return_url={System.Web.HttpUtility.UrlEncode(data.ReturnUrl)}";
        }
        var firstName = string.IsNullOrWhiteSpace(data.FirstName) ? null : data.FirstName;
        var greeting = firstName is null ? "Hei!" : $"Hei {firstName},";

        var model = new EmailTemplateModel(
            Heading: "Tilbakestill passordet ditt",
            Greeting: greeting,
            IntroParagraph: "Vi mottok en forespørsel om å tilbakestille passordet på din NETWORCO-konto. Klikk på knappen under for å velge et nytt passord.",
            CtaUrl: resetUrl,
            CtaLabel: "Velg nytt passord",
            FinePrintParagraph: "Lenken er gyldig i 2 timer. Hvis du ikke ba om å tilbakestille passordet, kan du trygt ignorere denne e-posten — passordet ditt forblir uendret.");

        await brevoEmail.SendEmailAsync(
            data.Email,
            data.FirstName,
            "Tilbakestill NETWORCO-passordet ditt",
            EmailTemplate.ToHtml(model),
            EmailTemplate.ToText(model),
            ct);
    }

    private async Task HandleNotificationEmail(EmailNotificationMessage data, CancellationToken ct)
    {
        // Generic notification path. Pull out the first URL in the body (if any)
        // so we can render it as a CTA + copy-the-link fallback inside the
        // branded template, and strip it from the prose so it isn't duplicated.
        var firstName = string.IsNullOrWhiteSpace(data.FirstName) ? null : data.FirstName;
        var greeting = firstName is null ? "Hei!" : $"Hei {firstName},";

        var (introWithoutUrl, ctaUrl) = ExtractFirstUrl(data.Body);

        var model = new EmailTemplateModel(
            Heading: data.Subject,
            Greeting: greeting,
            IntroParagraph: string.IsNullOrWhiteSpace(introWithoutUrl) ? data.Body : introWithoutUrl,
            CtaUrl: ctaUrl,
            CtaLabel: ctaUrl is null ? null : "Åpne lenken",
            FinePrintParagraph: null);

        await brevoEmail.SendEmailAsync(
            data.Email,
            data.FirstName ?? data.Email,
            data.Subject,
            EmailTemplate.ToHtml(model),
            EmailTemplate.ToText(model),
            ct);
    }

    private static readonly System.Text.RegularExpressions.Regex BodyUrlRegex = new(
        @"(https?://[^\s]+)",
        System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>
    /// Extracts the first URL found in a notification body so it can be
    /// surfaced as a CTA button. Cleans up trailing labels like "Link:" so the
    /// remaining prose reads naturally without the URL embedded.
    /// </summary>
    private static (string Body, string? Url) ExtractFirstUrl(string body)
    {
        if (string.IsNullOrEmpty(body)) return (body, null);
        var match = BodyUrlRegex.Match(body);
        if (!match.Success) return (body, null);

        // Drop the URL and trim a trailing "Link:" / "Lenke:" label that becomes
        // dangling after the URL is removed.
        var without = body.Remove(match.Index, match.Length);
        without = System.Text.RegularExpressions.Regex.Replace(
            without,
            @"\s*(Link|Lenke|URL)\s*:\s*$",
            string.Empty,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Multiline);
        return (without.Trim(), match.Value);
    }
}

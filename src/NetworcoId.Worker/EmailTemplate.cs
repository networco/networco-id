using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworcoId.Worker;

/// <summary>
/// Structured input for the branded NETWORCO email template. Each handler
/// builds one of these and asks the template to render both an HTML body
/// (styled with brand tokens, click-friendly CTA + copy-the-link fallback)
/// and a plaintext body for clients that don't render HTML.
/// </summary>
public sealed record EmailTemplateModel(
    string Heading,
    string Greeting,
    string IntroParagraph,
    string? CtaUrl = null,
    string? CtaLabel = null,
    string? FinePrintParagraph = null);

/// <summary>
/// Brand-aligned email renderer. Colour tokens mirror docs/design/brand-tokens.json
/// in the networco-app repo (Baby blue surface, NETWORCO blue text, Coral CTA,
/// Cognac accents, Authority dark for headings).
/// </summary>
public static class EmailTemplate
{
    // Brand tokens (kept inline so the email is self-contained with no external CSS).
    private const string BgPage         = "#EEF5F8"; // networco-baby-50 — outer surface
    private const string BgCard         = "#FFFFFF";
    private const string BorderSoft     = "#D6E5EC"; // networco-baby-100
    private const string TextHeading    = "#253B52"; // networco-authority-dark
    private const string TextBody       = "#355371"; // networco-dark
    private const string TextMuted      = "#6E9AAE"; // networco-baby-400
    private const string CtaBg          = "#FF6F61"; // networco-coral
    private const string CtaText        = "#FFFFFF";
    private const string AccentCognac   = "#7F5F53"; // networco-cognac
    private const string LinkBg         = "#F5FAFC"; // very pale baby blue for the copy-link box

    private static readonly Regex UrlRegex = new(
        @"(https?://[^\s]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Builds the HTML body. Uses table-based layout for broad email-client
    /// compatibility (Outlook, Gmail mobile, Apple Mail). Inline styles only —
    /// no external CSS or web fonts.
    /// </summary>
    public static string ToHtml(EmailTemplateModel model)
    {
        var greeting = WebUtility.HtmlEncode(model.Greeting);
        var heading = WebUtility.HtmlEncode(model.Heading);
        var intro = LinkifyAndEncode(model.IntroParagraph);
        var finePrint = string.IsNullOrWhiteSpace(model.FinePrintParagraph)
            ? null
            : LinkifyAndEncode(model.FinePrintParagraph);

        var sb = new StringBuilder(2048);

        sb.Append("<!DOCTYPE html><html lang=\"nb\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>");
        sb.Append(heading);
        sb.Append("</title></head>");
        sb.Append($"<body style=\"margin:0;padding:0;background-color:{BgPage};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:{TextBody};\">");

        // Outer table — gives consistent centering across clients.
        sb.Append("<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\"");
        sb.Append($" style=\"background-color:{BgPage};padding:32px 16px;\">");
        sb.Append("<tr><td align=\"center\">");

        // Card.
        sb.Append("<table role=\"presentation\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\"");
        sb.Append($" style=\"max-width:600px;width:100%;background-color:{BgCard};border:1px solid {BorderSoft};border-radius:12px;overflow:hidden;\">");

        // Header strip with brand mark.
        sb.Append($"<tr><td style=\"padding:24px 32px;border-bottom:1px solid {BorderSoft};\">");
        sb.Append($"<div style=\"font-size:18px;font-weight:700;letter-spacing:0.04em;color:{TextHeading};\">NETWORCO</div>");
        sb.Append($"<div style=\"font-size:12px;color:{AccentCognac};margin-top:2px;\">Vi kobler ungdom og arbeidsgivere</div>");
        sb.Append("</td></tr>");

        // Body.
        sb.Append("<tr><td style=\"padding:32px;\">");
        sb.Append($"<h1 style=\"margin:0 0 8px 0;font-size:22px;line-height:1.3;color:{TextHeading};\">{heading}</h1>");
        sb.Append($"<p style=\"margin:0 0 16px 0;font-size:15px;color:{TextBody};\">{greeting}</p>");
        sb.Append($"<p style=\"margin:0 0 24px 0;font-size:15px;line-height:1.55;color:{TextBody};\">{intro}</p>");

        // CTA button + copy-link fallback.
        if (!string.IsNullOrWhiteSpace(model.CtaUrl) && !string.IsNullOrWhiteSpace(model.CtaLabel))
        {
            var ctaUrl = WebUtility.HtmlEncode(model.CtaUrl);
            var ctaLabel = WebUtility.HtmlEncode(model.CtaLabel);

            sb.Append("<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 auto 24px auto;\"><tr><td align=\"center\">");
            sb.Append($"<a href=\"{ctaUrl}\" target=\"_blank\" rel=\"noopener\" style=\"display:inline-block;background-color:{CtaBg};color:{CtaText};text-decoration:none;font-weight:600;font-size:15px;padding:14px 28px;border-radius:10px;\">");
            sb.Append(ctaLabel);
            sb.Append("</a>");
            sb.Append("</td></tr></table>");

            sb.Append($"<p style=\"margin:0 0 8px 0;font-size:13px;color:{TextMuted};\">Fungerer ikke knappen? Kopier denne lenken inn i nettleseren din:</p>");
            sb.Append($"<div style=\"background-color:{LinkBg};border:1px solid {BorderSoft};border-radius:8px;padding:12px 14px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:12px;color:{TextHeading};word-break:break-all;\">");
            sb.Append($"<a href=\"{ctaUrl}\" target=\"_blank\" rel=\"noopener\" style=\"color:{TextHeading};text-decoration:underline;\">{ctaUrl}</a>");
            sb.Append("</div>");
        }

        if (finePrint is not null)
        {
            sb.Append($"<p style=\"margin:24px 0 0 0;font-size:13px;color:{TextMuted};line-height:1.55;\">{finePrint}</p>");
        }

        sb.Append("</td></tr>");

        // Footer.
        sb.Append($"<tr><td style=\"padding:20px 32px;border-top:1px solid {BorderSoft};font-size:12px;color:{TextMuted};\">");
        sb.Append("Du mottok denne e-posten fordi noen brukte e-postadressen din på NETWORCO. ");
        sb.Append("Hvis dette ikke var deg, kan du trygt slette meldingen.");
        sb.Append("</td></tr>");

        sb.Append("</table>");
        sb.Append("</td></tr></table></body></html>");

        return sb.ToString();
    }

    /// <summary>
    /// Builds the plaintext body for clients that don't render HTML (and as
    /// the multipart/alternative fallback).
    /// </summary>
    public static string ToText(EmailTemplateModel model)
    {
        var sb = new StringBuilder(512);
        sb.AppendLine("NETWORCO — Vi kobler ungdom og arbeidsgivere");
        sb.AppendLine(new string('-', 56));
        sb.AppendLine();
        sb.AppendLine(model.Heading);
        sb.AppendLine();
        sb.AppendLine(model.Greeting);
        sb.AppendLine();
        sb.AppendLine(model.IntroParagraph);
        sb.AppendLine();

        if (!string.IsNullOrWhiteSpace(model.CtaUrl) && !string.IsNullOrWhiteSpace(model.CtaLabel))
        {
            sb.Append(model.CtaLabel);
            sb.AppendLine(":");
            sb.AppendLine(model.CtaUrl);
            sb.AppendLine();
        }

        if (!string.IsNullOrWhiteSpace(model.FinePrintParagraph))
        {
            sb.AppendLine(model.FinePrintParagraph);
            sb.AppendLine();
        }

        sb.AppendLine("--");
        sb.AppendLine("Du mottok denne e-posten fordi noen brukte e-postadressen din på NETWORCO.");
        sb.AppendLine("Hvis dette ikke var deg, kan du trygt slette meldingen.");

        return sb.ToString();
    }

    /// <summary>
    /// HTML-encodes the body and turns bare URLs into clickable links.
    /// Keeps newlines as `<br>` for paragraph readability.
    /// </summary>
    private static string LinkifyAndEncode(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return string.Empty;
        var encoded = WebUtility.HtmlEncode(raw).Replace("\n", "<br>");
        return UrlRegex.Replace(encoded, m =>
            $"<a href=\"{m.Value}\" target=\"_blank\" rel=\"noopener\" style=\"color:{TextHeading};text-decoration:underline;\">{m.Value}</a>");
    }
}

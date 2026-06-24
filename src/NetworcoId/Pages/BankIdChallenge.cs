using System.Web;

namespace NetworcoId.Pages;

/// <summary>
/// Builds the BankID external-challenge link shared by the Login and Register
/// pages. Both must produce the same target so BankID resumes the original
/// /oauth/authorize flow after the eID completes — kept in one place so the two
/// pages can't drift apart.
/// </summary>
internal static class BankIdChallenge
{
    /// <summary>
    /// Returns <c>/auth/external/bankid?returnUrl=/oauth/authorize?...</c> carrying
    /// the OAuth request, or a bare <c>/auth/external/bankid</c> when there's no
    /// OAuth context (e.g. a direct visit).
    /// </summary>
    public static string BuildUrl(
        string? clientId,
        string? redirectUri,
        string? scope,
        string? state,
        string? codeChallenge,
        string? codeChallengeMethod,
        string? nonce)
    {
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
        {
            return "/auth/external/bankid";
        }

        var q = HttpUtility.ParseQueryString("");
        q["response_type"] = "code";
        q["client_id"] = clientId;
        q["redirect_uri"] = redirectUri;
        if (!string.IsNullOrEmpty(scope)) q["scope"] = scope;
        if (!string.IsNullOrEmpty(state)) q["state"] = state;
        if (!string.IsNullOrEmpty(codeChallenge)) q["code_challenge"] = codeChallenge;
        if (!string.IsNullOrEmpty(codeChallengeMethod)) q["code_challenge_method"] = codeChallengeMethod;
        if (!string.IsNullOrEmpty(nonce)) q["nonce"] = nonce;

        var authorizeUrl = "/oauth/authorize?" + q;
        return "/auth/external/bankid?returnUrl=" + Uri.EscapeDataString(authorizeUrl);
    }
}

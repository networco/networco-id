using NetworcoId.Models.Auth;

namespace NetworcoId.Services;

/// <summary>
/// Builds the human-readable Norwegian password-policy hint shown on the password
/// pages, derived from <see cref="NetworcoIdConfig"/> so the text always matches
/// what <c>PasswordValidator</c> actually enforces. Register renders a live
/// per-rule checklist instead; the other password pages use this one-liner.
/// </summary>
public static class PasswordPolicyText
{
    public static string BuildHint(NetworcoIdConfig config)
    {
        var parts = new List<string> { $"minst {config.MinPasswordLength} tegn" };
        if (config.RequireUppercase) parts.Add("stor bokstav");
        if (config.RequireLowercase) parts.Add("liten bokstav");
        if (config.RequireDigit) parts.Add("tall");
        if (config.RequireNonAlphanumeric) parts.Add("spesialtegn");

        // Join as Norwegian list style "a, b, c og d", then capitalise the first letter.
        var joined = parts.Count == 1
            ? parts[0]
            : string.Join(", ", parts.Take(parts.Count - 1)) + " og " + parts[^1];
        return char.ToUpper(joined[0]) + joined[1..];
    }
}

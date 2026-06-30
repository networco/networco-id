using System.Globalization;
using System.Text;

namespace NetworcoId.Services;

/// <summary>
/// Decides whether two names refer to the same person, used to decide when an account's
/// self-entered name diverges enough from the BankID legal name that the BankID name should
/// replace it (issue #104). Token-set based (NOT raw edit distance) so legitimate variants —
/// word order, added/dropped middle names, hyphenated/compound parts, and Norwegian
/// diacritics (ø/å/æ) — are treated as the same person and never clobbered. Mirrors the
/// equivalent util in networco-app.
/// </summary>
public static class NameMatch
{
    /// <summary>
    /// True when the two names plausibly refer to the same person: every token of the shorter
    /// name appears in the longer one (so order and extra middle names don't matter). When
    /// either name is empty we can't tell, so we conservatively return true (no overwrite).
    /// </summary>
    public static bool IsSamePerson(string? a, string? b)
    {
        var ta = Tokenize(a);
        var tb = Tokenize(b);
        if (ta.Count == 0 || tb.Count == 0) return true; // not enough info — don't treat as divergent
        var (small, large) = ta.Count <= tb.Count ? (ta, tb) : (tb, ta);
        return small.IsSubsetOf(large);
    }

    /// <summary>Inverse of <see cref="IsSamePerson"/> — the names clearly differ.</summary>
    public static bool IsDivergent(string? a, string? b) => !IsSamePerson(a, b);

    private static HashSet<string> Tokenize(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return new HashSet<string>();
        return s.Replace('-', ' ')
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(FoldToken)
            .Where(t => t.Length > 0)
            .ToHashSet();
    }

    private static string FoldToken(string token)
    {
        // Norwegian letters first (not removed by Unicode decomposition), then strip remaining accents.
        var lowered = token.ToLowerInvariant()
            .Replace("ø", "o").Replace("æ", "ae").Replace("å", "a");
        var sb = new StringBuilder(lowered.Length);
        foreach (var ch in lowered.Normalize(NormalizationForm.FormD))
        {
            if (CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.NonSpacingMark)
                sb.Append(ch);
        }
        return sb.ToString().Normalize(NormalizationForm.FormC);
    }
}

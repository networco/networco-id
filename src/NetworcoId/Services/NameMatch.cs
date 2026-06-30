namespace NetworcoId.Services;

/// <summary>
/// Case- and whitespace-insensitive name similarity, used to decide whether an
/// account's self-entered name diverges too much from the BankID-verified legal name
/// and the BankID name should replace it (issue #104). Mirrors the util in networco-app.
/// </summary>
public static class NameMatch
{
    /// <summary>At/above this similarity the names are treated as the same person.</summary>
    public const double DefaultThreshold = 0.7;

    /// <summary>Normalized Levenshtein similarity in [0,1] (1 = identical after normalization).</summary>
    public static double Similarity(string? a, string? b)
    {
        var x = Normalize(a);
        var y = Normalize(b);
        if (x.Length == 0 && y.Length == 0) return 1.0;
        if (x.Length == 0 || y.Length == 0) return 0.0;
        var distance = Levenshtein(x, y);
        var maxLen = Math.Max(x.Length, y.Length);
        return 1.0 - (double)distance / maxLen;
    }

    /// <summary>True when the two names are similar enough to treat as the same person.</summary>
    public static bool IsCloseEnough(string? a, string? b, double threshold = DefaultThreshold)
        => Similarity(a, b) >= threshold;

    private static string Normalize(string? s)
        => string.IsNullOrWhiteSpace(s)
            ? string.Empty
            : string.Join(' ', s.Trim().ToLowerInvariant()
                .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static int Levenshtein(string a, string b)
    {
        var prev = new int[b.Length + 1];
        var curr = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++) prev[j] = j;
        for (var i = 1; i <= a.Length; i++)
        {
            curr[0] = i;
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                curr[j] = Math.Min(Math.Min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            (prev, curr) = (curr, prev);
        }
        return prev[b.Length];
    }
}

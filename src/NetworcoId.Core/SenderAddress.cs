namespace NetworcoId.Core;

/// <summary>
/// Reading a configured mail sender.
///
/// Lives in Core because it is pure string handling with no dependency on
/// any provider — and because it must be testable without dragging the
/// worker's transport dependencies into the test assembly.
/// </summary>
public static class SenderAddress
{
    /// <summary>
    /// Splits a configured sender into display name and bare address.
    ///
    /// Accepts both "Name &lt;addr@example&gt;" and a bare "addr@example",
    /// and strips surrounding quotes: the deploy's env file quotes the
    /// value because it contains a space, and not every loader unquotes it.
    /// An embedded name wins over <paramref name="fallbackName"/> — it was
    /// written next to the address it belongs to.
    ///
    /// This exists because postbud takes the sender as a bare ADDRESS with
    /// the display name as a separate field. Handing it the whole
    /// "Name &lt;addr&gt;" string gets the message refused, and the symptom
    /// is mail that silently stops arriving.
    /// </summary>
    public static (string Name, string Email) Split(string sender, string fallbackName)
    {
        var value = (sender ?? string.Empty).Trim().Trim('"');

        var open = value.IndexOf('<');
        if (open < 0)
        {
            return (fallbackName, value);
        }

        var name = value[..open].Trim().Trim('"');
        var email = value[(open + 1)..].TrimEnd().TrimEnd('>').Trim();
        return (string.IsNullOrWhiteSpace(name) ? fallbackName : name, email);
    }
}

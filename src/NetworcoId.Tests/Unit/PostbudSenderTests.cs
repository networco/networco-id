using NetworcoId.Core;
using Xunit;

namespace NetworcoId.Tests.Unit;

/// <summary>
/// postbud takes <c>from</c> as a bare ADDRESS, with the display name as a
/// separate field. The deploy's env file configures the sender as
/// "Name &lt;addr&gt;", so passing the configured string straight through
/// would send the display name as part of the address — postbud refuses it,
/// and every password reset stops arriving with nothing but a 4xx in the
/// worker log to say why.
/// </summary>
public class PostbudSenderTests
{
    [Fact]
    public void A_display_name_sender_is_split_into_name_and_address()
    {
        var (name, email) = SenderAddress.Split(
            "Networco <noreply@test.postbud.networco.no>", "FALLBACK");

        Assert.Equal("Networco", name);
        Assert.Equal("noreply@test.postbud.networco.no", email);
    }

    [Fact]
    public void A_bare_address_keeps_the_configured_name()
    {
        var (name, email) = SenderAddress.Split(
            "noreply@test.postbud.networco.no", "NETWORCO");

        Assert.Equal("NETWORCO", name);
        Assert.Equal("noreply@test.postbud.networco.no", email);
    }

    /// <summary>
    /// The env file quotes the value because it contains a space. The deploy
    /// strips the outer pair, but a local .env loader may not — and a stray
    /// quote inside an address is refused just as firmly as a display name.
    /// </summary>
    [Fact]
    public void Surrounding_quotes_do_not_reach_the_address()
    {
        var (name, email) = SenderAddress.Split(
            "\"Networco <noreply@test.postbud.networco.no>\"", "FALLBACK");

        Assert.Equal("Networco", name);
        Assert.Equal("noreply@test.postbud.networco.no", email);
    }

    [Fact]
    public void An_empty_display_name_falls_back_rather_than_sending_nothing()
    {
        var (name, email) = SenderAddress.Split(
            "<noreply@test.postbud.networco.no>", "NETWORCO");

        Assert.Equal("NETWORCO", name);
        Assert.Equal("noreply@test.postbud.networco.no", email);
    }
}

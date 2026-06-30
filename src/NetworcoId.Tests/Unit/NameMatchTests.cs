using NetworcoId.Services;
using Xunit;

namespace NetworcoId.Tests.Unit;

/// <summary>
/// Name similarity used to decide when an account's self-entered name diverges far
/// enough from the BankID legal name that the BankID name should replace it (issue #104).
/// </summary>
public class NameMatchTests
{
    [Fact]
    public void Identical_AreCloseEnough()
    {
        Assert.Equal(1.0, NameMatch.Similarity("Ola Nordmann", "Ola Nordmann"));
        Assert.True(NameMatch.IsCloseEnough("Ola Nordmann", "Ola Nordmann"));
    }

    [Fact]
    public void CaseAndWhitespace_Ignored()
    {
        Assert.True(NameMatch.IsCloseEnough("  ola   NORDMANN ", "Ola Nordmann"));
    }

    [Fact]
    public void MinorTypo_IsStillCloseEnough()
    {
        Assert.True(NameMatch.IsCloseEnough("Ola Nordman", "Ola Nordmann"));
    }

    [Fact]
    public void CompletelyDifferent_IsNotCloseEnough()
    {
        Assert.False(NameMatch.IsCloseEnough("Kari Hansen", "Ola Nordmann"));
    }

    [Fact]
    public void EmptyVsNonEmpty_IsNotCloseEnough()
    {
        Assert.False(NameMatch.IsCloseEnough("", "Ola Nordmann"));
        Assert.Equal(0.0, NameMatch.Similarity(null, "Ola Nordmann"));
    }
}

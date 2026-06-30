using NetworcoId.Services;
using Xunit;

namespace NetworcoId.Tests.Unit;

/// <summary>
/// Token-set "same person" check (issue #104): legitimate name variants must NOT count as
/// divergent (or we'd clobber a correct name); genuinely different names must.
/// </summary>
public class NameMatchTests
{
    [Theory]
    [InlineData("Ola Nordmann", "Ola Nordmann")]            // identical
    [InlineData("  ola   NORDMANN ", "Ola Nordmann")]       // case/space
    [InlineData("Nordmann Ola", "Ola Nordmann")]            // word order
    [InlineData("Ola Nordmann", "Ola Kristian Nordmann")]   // added middle name
    [InlineData("Anne Berg", "Anne-Marie Berg")]            // hyphenated/compound
    [InlineData("Ase Bjorgen", "Åse Bjørgen")]              // ø/å diacritics
    [InlineData("Ola", "")]                                 // missing part → not enough info
    public void LegitimateVariants_AreSamePerson_NotDivergent(string a, string b)
    {
        Assert.True(NameMatch.IsSamePerson(a, b));
        Assert.False(NameMatch.IsDivergent(a, b));
    }

    [Theory]
    [InlineData("Kari Hansen", "Ola Nordmann")]             // completely different
    [InlineData("Fake Name", "Ola Nordmann")]              // self entered a fake name
    public void DifferentNames_AreDivergent(string a, string b)
    {
        Assert.True(NameMatch.IsDivergent(a, b));
        Assert.False(NameMatch.IsSamePerson(a, b));
    }
}

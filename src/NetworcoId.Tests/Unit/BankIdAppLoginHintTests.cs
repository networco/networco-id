using NetworcoId.Endpoints;
using Xunit;

namespace NetworcoId.Tests.Unit;

/// <summary>
/// BankID started from our mobile app gets login_hint so it opens the BankID app; a browser
/// login must not (desktop users may not have the BankID app on that device).
/// </summary>
public class BankIdAppLoginHintTests
{
    [Theory]
    [InlineData("/oauth/authorize?client_id=c&redirect_uri=networco%3A%2F%2Fauth%2Fcallback&state=s")]
    [InlineData("/oauth/authorize?client_id=c&redirect_uri=networco-test%3A%2F%2Fauth%2Fcallback")]
    public void CustomSchemeRedirect_IsApp(string returnUrl) =>
        Assert.True(ExternalAuthEndpoints.IsNativeAppAuthorizeReturn(returnUrl));

    [Theory]
    [InlineData("/oauth/authorize?client_id=c&redirect_uri=https%3A%2F%2Fnetworco.no%2Fauth%2Fcallback")]
    [InlineData("/oauth/authorize?client_id=c&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback")]
    [InlineData("/oauth/authorize?client_id=c")]
    [InlineData("/oauth/authorize")]
    [InlineData("/somewhere?redirect_uri=networco%3A%2F%2Fauth%2Fcallback")]
    [InlineData("")]
    [InlineData(null)]
    public void BrowserOrInvalid_IsNotApp(string? returnUrl) =>
        Assert.False(ExternalAuthEndpoints.IsNativeAppAuthorizeReturn(returnUrl));
}

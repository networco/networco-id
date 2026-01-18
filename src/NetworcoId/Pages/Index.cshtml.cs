using System.Reflection;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Models.Auth;
using Microsoft.Extensions.Options;

namespace NetworcoId.Pages;

public class IndexModel(IOptions<NetworcoIdConfig> config) : PageModel
{
    public string Version { get; set; } = "0.0.0.0";
    public string BaseUrl { get; set; } = config.Value.BaseUrl;

    public void OnGet()
    {
        Version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.1.0";
    }
}

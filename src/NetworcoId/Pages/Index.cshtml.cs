using System.Reflection;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace NetworcoId.Pages;

public class IndexModel : PageModel
{
    public string Version { get; set; } = "0.0.0.0";

    public void OnGet()
    {
        Version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.1.0";
    }
}

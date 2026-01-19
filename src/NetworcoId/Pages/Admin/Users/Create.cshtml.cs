using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Entities;
using NetworcoId.Services.Audit;
using NetworcoId.Infrastructure.Auth;
using NetworcoId.Core.Security;

namespace NetworcoId.Pages.Admin.Users;

[AdminAuth]
public class CreateModel : PageModel
{
    private readonly AuthDbContext _context;
    private readonly IAuditService _auditService;
    private readonly IPasswordHasher _passwordHasher;

    public CreateModel(AuthDbContext context, IAuditService auditService, IPasswordHasher passwordHasher)
    {
        _context = context;
        _auditService = auditService;
        _passwordHasher = passwordHasher;
    }

    [BindProperty]
    public UserEntity UserData { get; set; } = new() { Email = "", FirstName = "", LastName = "" };

    [BindProperty]
    public string? Password { get; set; }

    [BindProperty]
    public List<string> SelectedRoles { get; set; } = new();

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrWhiteSpace(Password))
        {
            ModelState.AddModelError("Password", "Password is required for new users.");
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        // Check for existing user
        if (_context.Users.Any(u => u.Email == UserData.Email))
        {
            ModelState.AddModelError("UserData.Email", "A user with this email already exists.");
            return Page();
        }

        var newUser = new UserEntity
        {
            Id = Guid.NewGuid(),
            Email = UserData.Email,
            FirstName = UserData.FirstName,
            LastName = UserData.LastName,
            NationalId = UserData.NationalId,
            PhoneNumber = UserData.PhoneNumber,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            Roles = SelectedRoles.Where(r => !string.IsNullOrWhiteSpace(r)).ToList(),
            AddressStreetAddress = UserData.AddressStreetAddress,
            AddressPostalCode = UserData.AddressPostalCode,
            AddressLocality = UserData.AddressLocality,
            AddressRegion = UserData.AddressRegion,
            AddressCountry = UserData.AddressCountry,
            AddressFormatted = $"{UserData.AddressStreetAddress}, {UserData.AddressPostalCode} {UserData.AddressLocality}, {UserData.AddressRegion}, {UserData.AddressCountry}"
                .Replace(", ,", ",")
                .Trim(',', ' ')
        };

        var credential = new UserCredentialEntity
        {
            Id = newUser.Id,
            PasswordHash = _passwordHasher.HashPassword(Password!),
            CreatedAt = DateTimeOffset.UtcNow,
            MustChangePassword = true
        };

        _context.Users.Add(newUser);
        _context.UserCredentials.Add(credential);
        
        await _context.SaveChangesAsync();
        await _auditService.LogAsync("UserCreated", $"New user created via admin: {newUser.Email}", newUser.Id);

        TempData["StatusMessage"] = $"User {newUser.Email} has been created successfully.";
        return RedirectToPage("./Index");
    }
}

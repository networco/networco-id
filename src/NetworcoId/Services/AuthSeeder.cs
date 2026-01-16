using Microsoft.EntityFrameworkCore;
using NetworcoId.Core.Security;
using NetworcoId.Infrastructure.Database;
using NetworcoId.Models.Auth;
using NetworcoId.Models.Entities;
using NetworcoId.Core.Models;

namespace NetworcoId.Services;

/// <summary>
/// Authentication seeder interface.
/// </summary>
public interface IAuthSeeder
{
    Task SeedAsync();
}

/// <summary>
/// Seeds NETWORCO ID authentication users.
/// Creates test users with known credentials for NETWORCO ID.
/// </summary>
public class AuthSeeder : IAuthSeeder
{
    private readonly AuthDbContext _context;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IClientManagementService _clientService;

    public AuthSeeder(
        AuthDbContext context,
        IPasswordHasher passwordHasher,
        IClientManagementService clientService)
    {
        _context = context;
        _passwordHasher = passwordHasher;
        _clientService = clientService;
    }

    /// <summary>
    /// Seeds NETWORCO ID users with test credentials.
    /// </summary>
    public async Task SeedAsync()
    {
        await _clientService.SyncFromConfigAsync();
        await SeedUsersAsync();
    }

    private Task SeedClientsAsync() => Task.CompletedTask; // Replaced by _clientService.SyncFromConfigAsync()

    private async Task SeedUsersAsync()
    {
        Console.WriteLine("Seeding NETWORCO ID authentication users...");

        var devUsers = new[]
        {
            // Admin user
            new
            {
                Email = "admin@networco.dev",
                FirstName = "Admin",
                LastName = "User",
                NationalId = "12345678901",
                PhoneNumber = "+4798765432",
                // Removed: Role - authorization handled by resource server
                Password = "Admin123!"
            },

            // Youth users
            new
            {
                Email = "emma.larsen@networco.dev",
                FirstName = "Emma",
                LastName = "Larsen",
                NationalId = "15120512345",
                PhoneNumber = "+4712345678",
                // Removed: Role - authorization handled by resource server
                Password = "Test123!"
            },
            new
            {
                Email = "ole.nordmann@networco.dev",
                FirstName = "Ole",
                LastName = "Nordmann",
                NationalId = "02030467890",
                PhoneNumber = "+4798765431",
                // Removed: Role - authorization handled by resource server
                Password = "Test123!"
            },

            // Employer users
            new
            {
                Email = "marte.hansen@kiwi.no",
                FirstName = "Marte",
                LastName = "Hansen",
                NationalId = "11119712345",
                PhoneNumber = "+4711223344",
                // Removed: Role - authorization handled by resource server
                Password = "Test123!"
            },
            new
            {
                Email = "lars.petersen@coop.no",
                FirstName = "Lars",
                LastName = "Petersen",
                NationalId = "22038856789",
                PhoneNumber = "+4755667788",
                // Removed: Role - authorization handled by resource server
                Password = "Test123!"
            }
        };

        foreach (var userData in devUsers)
        {
            // Check if user already exists
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == userData.Email);

            if (existingUser != null)
            {
                Console.WriteLine($"User {userData.Email} already exists, skipping...");
                continue;
            }

            // Create user
            var user = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = userData.Email,
                FirstName = userData.FirstName,
                LastName = userData.LastName,
                NationalId = userData.NationalId,
                PhoneNumber = userData.PhoneNumber,
                // Removed: RoleId - authorization handled by resource server
                CreatedAt = DateTimeOffset.UtcNow
            };

            // Create credentials
            var credential = new UserCredentialEntity
            {
                Id = user.Id, // 1:1 relationship
                PasswordHash = _passwordHasher.HashPassword(userData.Password),
                CreatedAt = DateTimeOffset.UtcNow
            };

            _context.Users.Add(user);
            _context.UserCredentials.Add(credential);

            Console.WriteLine($"Created user: {userData.Email} ({userData.FirstName} {userData.LastName})");
        }

        await _context.SaveChangesAsync();
        Console.WriteLine("Authentication users seeded successfully!");
    }
}
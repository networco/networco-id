using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace NetworcoId.Core.Security;

public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash);
    bool IsArgon2id(string hash);
}

public class PasswordHasher : IPasswordHasher
{
    // Legacy PBKDF2 Constants
    private const int LegacySaltSize = 16;
    private const int LegacyHashSize = 32;
    private const int LegacyIterations = 100_000;

    // Argon2id Constants (OWASP Recommendations)
    private const int ArgonSaltSize = 16;
    private const int ArgonKeySize = 32;
    private const int ArgonDegreeOfParallelism = 4; // 4 threads
    private const int ArgonIterations = 3; // 3 passes
    private const int ArgonMemorySize = 64 * 1024; // 64 MB

    public string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty", nameof(password));

        // Use Argon2id for new passwords
        return HashWithArgon2id(password);
    }

    public bool VerifyPassword(string password, string hash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            return false;

        try
        {
            if (IsArgon2id(hash))
            {
                return VerifyArgon2id(password, hash);
            }
            else
            {
                // Fallback to PBKDF2 verification for existing users
                return VerifyLegacyPbkdf2(password, hash);
            }
        }
        catch
        {
            return false;
        }
    }

    public bool IsArgon2id(string hash)
    {
        // Argon2id hashes usually start with $argon2id$ or we can check format
        // Our PBKDF2 format is just Base64(Salt + Hash)
        // Let's adopt a standard format for Argon2: $argon2id$v=19$m=...,t=...,p=...$salt$hash
        // OR simpler custom format: $argon2id${Base64(Salt)}{Base64(Hash)}
        // Ideally we follow PHC string format. 
        // But Konscious.Argon2 produces raw bytes.
        
        // Simple heuristic: If it starts with "$argon2id", it's new.
        return hash.StartsWith("$argon2id");
    }

    private string HashWithArgon2id(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(ArgonSaltSize);

        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = ArgonDegreeOfParallelism,
            Iterations = ArgonIterations,
            MemorySize = ArgonMemorySize
        };

        byte[] hash = argon2.GetBytes(ArgonKeySize);
        
        // Format: $argon2id$v=19$m={m},t={t},p={p}${b64salt}${b64hash}
        // This is a standard-ish representation
        var b64Salt = Convert.ToBase64String(salt);
        var b64Hash = Convert.ToBase64String(hash);

        return $"$argon2id$v=19$m={ArgonMemorySize},t={ArgonIterations},p={ArgonDegreeOfParallelism}${b64Salt}${b64Hash}";
    }

    private bool VerifyArgon2id(string password, string formattedHash)
    {
        // Parse format: $argon2id$v=19$m={m},t={t},p={p}${b64salt}${b64hash}
        var parts = formattedHash.Split('$');
        if (parts.Length != 6) return false;

        // parts[0] is empty (leading $)
        // parts[1] is "argon2id"
        // parts[2] is "v=19"
        // parts[3] is params "m=...,t=...,p=..."
        // parts[4] is salt
        // parts[5] is hash

        var paramParts = parts[3].Split(',');
        var memory = int.Parse(paramParts[0].Split('=')[1]);
        var iterations = int.Parse(paramParts[1].Split('=')[1]);
        var parallelism = int.Parse(paramParts[2].Split('=')[1]);

        var salt = Convert.FromBase64String(parts[4]);
        var storedHash = Convert.FromBase64String(parts[5]);

        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = parallelism,
            Iterations = iterations,
            MemorySize = memory
        };

        var computedHash = argon2.GetBytes(ArgonKeySize);

        return CryptographicOperations.FixedTimeEquals(computedHash, storedHash);
    }

    private bool VerifyLegacyPbkdf2(string password, string hash)
    {
        try
        {
            byte[] combined = Convert.FromBase64String(hash);
            
            if (combined.Length != LegacySaltSize + LegacyHashSize)
                return false;
            
            byte[] salt = new byte[LegacySaltSize];
            Buffer.BlockCopy(combined, 0, salt, 0, LegacySaltSize);
            
            byte[] storedHash = new byte[LegacyHashSize];
            Buffer.BlockCopy(combined, LegacySaltSize, storedHash, 0, LegacyHashSize);
            
            byte[] computedHash = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: LegacyIterations,
                numBytesRequested: LegacyHashSize);
            
            return CryptographicOperations.FixedTimeEquals(computedHash, storedHash);
        }
        catch
        {
            return false;
        }
    }
}

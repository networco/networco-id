using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using NetworcoId.Core.Security;
using Xunit;

namespace NetworcoId.Tests.Unit;

public class PasswordHasherTests
{
    private readonly PasswordHasher _hasher;

    public PasswordHasherTests()
    {
        _hasher = new PasswordHasher();
    }

    [Fact]
    public void HashPassword_ReturnsArgon2idHash()
    {
        var password = "TestPassword123!";
        var hash = _hasher.HashPassword(password);

        Assert.NotNull(hash);
        Assert.StartsWith("$argon2id", hash);
        Assert.True(_hasher.IsArgon2id(hash));
    }

    [Fact]
    public void VerifyPassword_WithArgon2idHash_ReturnsTrue()
    {
        var password = "TestPassword123!";
        var hash = _hasher.HashPassword(password);

        Assert.True(_hasher.VerifyPassword(password, hash));
    }

    [Fact]
    public void VerifyPassword_WithArgon2idHash_ReturnsFalseForWrongPassword()
    {
        var password = "TestPassword123!";
        var hash = _hasher.HashPassword(password);

        Assert.False(_hasher.VerifyPassword("WrongPassword", hash));
    }

    [Fact]
    public void VerifyPassword_WithLegacyPbkdf2Hash_ReturnsTrue()
    {
        // Setup legacy hash manually
        var password = "LegacyPassword123!";
        var legacyHash = CreateLegacyHash(password);

        Assert.False(_hasher.IsArgon2id(legacyHash), "Should be identified as legacy hash");
        Assert.True(_hasher.VerifyPassword(password, legacyHash));
    }

    [Fact]
    public void VerifyPassword_WithLegacyPbkdf2Hash_ReturnsFalseForWrongPassword()
    {
        var password = "LegacyPassword123!";
        var legacyHash = CreateLegacyHash(password);

        Assert.False(_hasher.VerifyPassword("WrongPassword", legacyHash));
    }

    private string CreateLegacyHash(string password)
    {
        // Re-implement legacy logic just for test setup
        const int SaltSize = 16;
        const int HashSize = 32;
        const int Iterations = 100_000;

        byte[] salt = new byte[SaltSize];
        // Use a fixed salt or random, doesn't matter for this test
        new Random().NextBytes(salt);
        
        byte[] hash = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: Iterations,
            numBytesRequested: HashSize);
        
        byte[] combined = new byte[SaltSize + HashSize];
        Buffer.BlockCopy(salt, 0, combined, 0, SaltSize);
        Buffer.BlockCopy(hash, 0, combined, SaltSize, HashSize);
        
        return Convert.ToBase64String(combined);
    }
}

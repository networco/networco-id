namespace NetworcoId.Core.Security;

/// <summary>
/// Service for validating password complexity.
/// </summary>
public interface IPasswordValidator
{
    (bool IsValid, string? ErrorMessage) Validate(string password, int minLength, bool requireDigit, bool requireUppercase, bool requireLowercase, bool requireNonAlphanumeric);
}

public class PasswordValidator : IPasswordValidator
{
    public (bool IsValid, string? ErrorMessage) Validate(string password, int minLength, bool requireDigit, bool requireUppercase, bool requireLowercase, bool requireNonAlphanumeric)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return (false, "Password is required.");
        }

        if (password.Length < minLength)
        {
            return (false, $"Password must be at least {minLength} characters long.");
        }

        if (requireUppercase && !password.Any(char.IsUpper))
        {
            return (false, "Password must contain at least one uppercase letter.");
        }

        if (requireLowercase && !password.Any(char.IsLower))
        {
            return (false, "Password must contain at least one lowercase letter.");
        }

        if (requireDigit && !password.Any(char.IsDigit))
        {
            return (false, "Password must contain at least one number.");
        }

        if (requireNonAlphanumeric && !password.Any(ch => !char.IsLetterOrDigit(ch)))
        {
            return (false, "Password must contain at least one special character.");
        }

        return (true, null);
    }
}

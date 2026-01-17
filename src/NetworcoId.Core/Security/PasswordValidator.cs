namespace NetworcoId.Core.Security;

/// <summary>
/// Service for validating password complexity.
/// </summary>
public interface IPasswordValidator
{
    (bool IsValid, string? ErrorMessage) Validate(string password);
}

public class PasswordValidator : IPasswordValidator
{
    public (bool IsValid, string? ErrorMessage) Validate(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return (false, "Password is required.");
        }

        if (password.Length < 12)
        {
            return (false, "Password must be at least 12 characters long.");
        }

        if (!password.Any(char.IsUpper))
        {
            return (false, "Password must contain at least one uppercase letter.");
        }

        if (!password.Any(char.IsLower))
        {
            return (false, "Password must contain at least one lowercase letter.");
        }

        if (!password.Any(char.IsDigit))
        {
            return (false, "Password must contain at least one number.");
        }

        if (!password.Any(ch => !char.IsLetterOrDigit(ch)))
        {
            return (false, "Password must contain at least one special character.");
        }

        return (true, null);
    }
}

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
            return (false, "Password is required");
        }

        if (password.Length < 8)
        {
            return (false, "Passordet må være minst 8 tegn");
        }

        if (!password.Any(char.IsUpper))
        {
            return (false, "Passordet må inneholde minst én stor bokstav");
        }

        if (!password.Any(char.IsLower))
        {
            return (false, "Passordet må inneholde minst én liten bokstav");
        }

        if (!password.Any(char.IsDigit))
        {
            return (false, "Passordet må inneholde minst ett tall");
        }

        return (true, null);
    }
}

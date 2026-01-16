namespace NetworcoId.Core.Models;

public enum UserRole
{
    Candidate = 0,
    Employer = 1,
    MunicipalAdmin = 2,
    SystemAdmin = 3
}

public record NetworcoIdUser
{
    public required string NationalId { get; init; }
    public required string FirstName { get; init; }
    public required string LastName { get; init; }
    public required string Email { get; init; }
    public string? PhoneNumber { get; init; }
    public required UserRole Role { get; init; }
    public string FullName => $"{FirstName} {LastName}";
    public string? Password { get; init; }
}

public record EmailVerificationMessage(string Email, string Token, string FirstName, string Type = "Verification");

public record PasswordResetMessage(string Email, string Token, string FirstName);

public record EmailNotificationMessage(string Email, string Subject, string Body, string? FirstName = null);

public static class NetworcoIdSubjects
{
    public const string StreamName = "NETWORCOID";
    public const string EmailVerify = "identity.email.verify";
    public const string EmailOtp = "identity.email.otp";
    public const string PasswordReset = "identity.email.reset";
    public const string EmailNotification = "identity.email.notification";
}

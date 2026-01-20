namespace NetworcoId.Services.Security;

/// <summary>
/// Interface for IP-based lockout management.
/// </summary>
public interface ILockoutService
{
    /// <summary>
    /// Checks if the given IP address is currently locked out.
    /// </summary>
    Task<bool> IsLockedAsync(string ipAddress);

    /// <summary>
    /// Records a failed login attempt for the given IP address.
    /// </summary>
    Task RecordFailureAsync(string ipAddress);

    /// <summary>
    /// Resets failed attempts for the given IP address.
    /// </summary>
    Task ResetAsync(string ipAddress);
}

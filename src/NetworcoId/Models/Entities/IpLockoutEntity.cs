using System.ComponentModel.DataAnnotations;

namespace NetworcoId.Models.Entities;

/// <summary>
/// Represents a distributed IP-based lockout for brute-force prevention.
/// </summary>
public class IpLockoutEntity
{
    [Key]
    public required string IpAddress { get; set; }

    public int FailedAttempts { get; set; }

    public DateTimeOffset LastAttemptAt { get; set; }

    public DateTimeOffset? LockedUntil { get; set; }
}

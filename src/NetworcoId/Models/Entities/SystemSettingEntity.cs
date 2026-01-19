namespace NetworcoId.Models.Entities;

/// <summary>
/// System setting entity for persisting application configuration.
/// </summary>
public class SystemSettingEntity
{
    public required string Key { get; set; }
    public required string Value { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

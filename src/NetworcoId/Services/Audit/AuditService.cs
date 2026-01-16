using NetworcoId.Models.Entities;

namespace NetworcoId.Services.Audit;

public interface IAuditService
{
    Task LogAsync(string eventType, string description, Guid? userId = null, string? metadata = null);
}

public class AuditService : IAuditService
{
    private readonly NetworcoId.Infrastructure.Database.AuthDbContext _context;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuditService(
        NetworcoId.Infrastructure.Database.AuthDbContext context,
        IHttpContextAccessor httpContextAccessor)
    {
        _context = context;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task LogAsync(string eventType, string description, Guid? userId = null, string? metadata = null)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        var ipAddress = httpContext?.Connection?.RemoteIpAddress?.ToString();
        var userAgent = httpContext?.Request?.Headers["User-Agent"].ToString();

        var auditLog = new AuditLogEntity
        {
            EventType = eventType,
            Description = description,
            UserId = userId,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = metadata
        };

        _context.AuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();
    }
}
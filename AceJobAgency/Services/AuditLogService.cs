using AceJobAgency.Models;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace AceJobAgency.Services
{
    public class AuditLogService
    {
        private readonly AuthDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuditLogService(AuthDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        // Log any user activity to the database
        public async Task LogActivityAsync(string userId, string activity, string? details = null)
        {
            try
            {
                var httpContext = _httpContextAccessor.HttpContext;

                var auditLog = new AuditLog
                {
                    UserId = userId,
                    Activity = activity,
                    Timestamp = DateTime.UtcNow,
                    IPAddress = httpContext?.Connection?.RemoteIpAddress?.ToString(),
                    UserAgent = httpContext?.Request?.Headers["User-Agent"].ToString(),
                    Details = details
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                // Log the error but don't throw - audit logging shouldn't break the app
                Console.WriteLine($"Audit log error: {ex.Message}");
            }
        }

        // Log successful login
        public async Task LogLoginAsync(string userId)
        {
            await LogActivityAsync(userId, "Login", "User logged in successfully");
        }

        // Log failed login attempt
        public async Task LogFailedLoginAsync(string userId, string reason)
        {
            await LogActivityAsync(userId, "Failed Login", reason);
        }

        // Log logout
        public async Task LogLogoutAsync(string userId)
        {
            await LogActivityAsync(userId, "Logout", "User logged out");
        }

        // Log registration
        public async Task LogRegistrationAsync(string userId)
        {
            await LogActivityAsync(userId, "Registration", "New user registered");
        }

        // Log password change
        public async Task LogPasswordChangeAsync(string userId)
        {
            await LogActivityAsync(userId, "Password Change", "User changed password");
        }

        // Log account lockout
        public async Task LogAccountLockoutAsync(string userId, int minutes)
        {
            await LogActivityAsync(userId, "Account Locked", $"Account locked for {minutes} minutes due to failed login attempts");
        }

        // Log 2FA verification
        public async Task Log2FAAsync(string userId, bool success)
        {
            var status = success ? "successful" : "failed";
            await LogActivityAsync(userId, "2FA Verification", $"2FA verification {status}");
        }

        // Log multiple device login detection
        public async Task LogMultipleDeviceLoginAsync(string userId)
        {
            await LogActivityAsync(userId, "Multiple Device Login", "User logged in from different device/browser");
        }

        // Log session timeout
        public async Task LogSessionTimeoutAsync(string userId)
        {
            await LogActivityAsync(userId, "Session Timeout", "User session expired due to inactivity");
        }
    }
}
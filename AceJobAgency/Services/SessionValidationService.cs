using AceJobAgency.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace AceJobAgency.Services
{
    // Service for validating user sessions and detecting multiple device logins
    public class SessionValidationService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuditLogService _auditLogService;

        public SessionValidationService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            AuditLogService auditLogService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _auditLogService = auditLogService;
        }

        // Validate if the current session is still valid
        public async Task<bool> ValidateSessionAsync(HttpContext httpContext, ApplicationUser user)
        {
            if (user == null)
                return false;

            // Get session ID from session storage
            var currentSessionId = httpContext.Session.GetString("SessionId");

            if (string.IsNullOrEmpty(currentSessionId))
                return false;

            // Check if session ID matches the one stored in database
            if (user.CurrentSessionId != currentSessionId)
            {
                // Different session detected - user logged in from another device
                await _auditLogService.LogActivityAsync(user.Id,
                    "Session Invalidated",
                    "User was logged out due to login from another device");

                return false;
            }

            return true;
        }

        // Create a new session for the user
        public async Task<string> CreateSessionAsync(HttpContext httpContext, ApplicationUser user)
        {
            var sessionId = System.Guid.NewGuid().ToString();

            // Store in HTTP session
            httpContext.Session.SetString("SessionId", sessionId);
            httpContext.Session.SetString("UserId", user.Id);
            httpContext.Session.SetString("UserEmail", user.Email);

            // Store in database
            user.CurrentSessionId = sessionId;
            await _userManager.UpdateAsync(user);

            return sessionId;
        }

        // Clear the user's session
        public async Task ClearSessionAsync(HttpContext httpContext, ApplicationUser user)
        {
            // Clear HTTP session
            httpContext.Session.Clear();

            // Clear session ID from database
            if (user != null)
            {
                user.CurrentSessionId = null;
                await _userManager.UpdateAsync(user);
            }
        }

        // Check if user has an active session elsewhere
        public bool HasActiveSessionElsewhere(ApplicationUser user, string currentSessionId)
        {
            return !string.IsNullOrEmpty(user.CurrentSessionId) &&
                   user.CurrentSessionId != currentSessionId;
        }
    }
}
using AceJobAgency.Models;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace AceJobAgency.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SessionValidationService _sessionValidationService;
        private readonly AuditLogService _auditLogService;

        public LogoutModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            SessionValidationService sessionValidationService,
            AuditLogService auditLogService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _sessionValidationService = sessionValidationService;
            _auditLogService = auditLogService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Get current user
            var user = await _userManager.GetUserAsync(User);

            if (user != null)
            {
                // Log logout activity
                await _auditLogService.LogLogoutAsync(user.Id);

                // Clear session
                await _sessionValidationService.ClearSessionAsync(HttpContext, user);
            }

            // Sign out
            await _signInManager.SignOutAsync();

            TempData["SuccessMessage"] = "You have been successfully logged out.";
            return RedirectToPage("/Login");
        }
    }
}
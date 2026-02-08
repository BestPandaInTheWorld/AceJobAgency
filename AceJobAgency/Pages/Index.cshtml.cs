using AceJobAgency.Models;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AceJobAgency.Pages
{
    [Authorize] 
    public class IndexModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly SessionValidationService _sessionValidationService;
        private readonly AuditLogService _auditLogService;

        public ApplicationUser CurrentUser { get; set; }
        public string DecryptedNRIC { get; set; }
        public int DaysUntilPasswordExpiry { get; set; }

        public IndexModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            SessionValidationService sessionValidationService,
            AuditLogService auditLogService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _sessionValidationService = sessionValidationService;
            _auditLogService = auditLogService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // GET CURRENT USER
            CurrentUser = await _userManager.GetUserAsync(User);

            if (CurrentUser == null)
            {
                await _signInManager.SignOutAsync();
                return RedirectToPage("/Login");
            }

            // VALIDATE SESSION
            var isValid = await _sessionValidationService.ValidateSessionAsync(HttpContext, CurrentUser);

            if (!isValid)
            {
                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                TempData["Error"] = "You have been logged out because you logged in from another device.";
                return RedirectToPage("/Login");
            }

            // DECRYPT NRIC FOR DISPLAY
            try
            {
                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("NRIC-Protection-Key");
                DecryptedNRIC = protector.Unprotect(CurrentUser.NRIC);
            }
            catch (Exception ex)
            {
                DecryptedNRIC = "Error decrypting NRIC";
                await _auditLogService.LogActivityAsync(CurrentUser.Id, "Decryption Error", $"Failed to decrypt NRIC: {ex.Message}");
            }

            // CHECK PASSWORD EXPIRY
            var daysSinceChange = (DateTime.UtcNow - CurrentUser.LastPasswordChangeDate).TotalDays;
            DaysUntilPasswordExpiry = 90 - (int)daysSinceChange;

            if (DaysUntilPasswordExpiry <= 7 && DaysUntilPasswordExpiry > 0)
            {
                TempData["PasswordWarning"] = $"Your password will expire in {DaysUntilPasswordExpiry} days. Please change it soon.";
            }

            return Page();
        }
    }
}
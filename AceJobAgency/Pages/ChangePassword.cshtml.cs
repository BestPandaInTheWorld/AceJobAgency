using AceJobAgency.Models;
using AceJobAgency.Services;
using AceJobAgency.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AceJobAgency.Pages
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuditLogService _auditLogService;

        [BindProperty]
        public ChangePassword CInput { get; set; }

        public string? ForceChangeMessage { get; set; }

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            AuditLogService auditLogService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _auditLogService = auditLogService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            if (TempData["ForcePasswordChange"] != null)
            {
                ForceChangeMessage = TempData["ForcePasswordChange"].ToString();
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            // VALIDATE PASSWORD COMPLEXITY (Same as registration)
            if (!IsPasswordValid(CInput.NewPassword))
            {
                ModelState.AddModelError("CInput.NewPassword",
                    "Password must be at least 12 characters with uppercase, lowercase, number, and special character.");
                return Page();
            }

            // CHECK MINIMUM PASSWORD AGE (10% marks - Advanced Features)
            var hoursSinceLastChange = (DateTime.UtcNow - user.LastPasswordChangeDate).TotalHours;

            if (hoursSinceLastChange < 24) // 1 day minimum
            {
                ModelState.AddModelError("",
                    $"You cannot change your password yet. Minimum 24 hours must pass since last change. Please wait {24 - (int)hoursSinceLastChange} more hours.");
                return Page();
            }

            // VERIFY CURRENT PASSWORD
            var isCurrentPasswordCorrect = await _userManager.CheckPasswordAsync(user, CInput.CurrentPassword);
            if (!isCurrentPasswordCorrect)
            {
                ModelState.AddModelError("CInput.CurrentPassword", "Current password is incorrect.");
                return Page();
            }

            // CHECK PASSWORD HISTORY 
            // Prevent reuse of last 2 passwords
            var passwordHasher = new PasswordHasher<ApplicationUser>();

            // Check against current password
            var matchesCurrent = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, CInput.NewPassword);
            if (matchesCurrent == PasswordVerificationResult.Success)
            {
                ModelState.AddModelError("CInput.NewPassword",
                    "You cannot reuse your current password. Please choose a different password.");
                return Page();
            }

            // Check against password history 1
            if (!string.IsNullOrEmpty(user.PasswordHistory1))
            {
                var matchesHistory1 = passwordHasher.VerifyHashedPassword(user, user.PasswordHistory1, CInput.NewPassword);
                if (matchesHistory1 == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("CInput.NewPassword",
                        "You cannot reuse one of your last 2 passwords. Please choose a different password.");
                    return Page();
                }
            }

            // Check against password history 2
            if (!string.IsNullOrEmpty(user.PasswordHistory2))
            {
                var matchesHistory2 = passwordHasher.VerifyHashedPassword(user, user.PasswordHistory2, CInput.NewPassword);
                if (matchesHistory2 == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("CInput.NewPassword",
                        "You cannot reuse one of your last 2 passwords. Please choose a different password.");
                    return Page();
                }
            }

            // CHANGE PASSWORD
            var result = await _userManager.ChangePasswordAsync(user, CInput.CurrentPassword, CInput.NewPassword);

            if (result.Succeeded)
            {
                // UPDATE PASSWORD HISTORY
                user.PasswordHistory2 = user.PasswordHistory1;
                user.PasswordHistory1 = user.PasswordHash;   
                user.LastPasswordChangeDate = DateTime.UtcNow;
                user.NextPasswordChangeDate = DateTime.UtcNow.AddDays(90); 

                await _userManager.UpdateAsync(user);

                // LOG PASSWORD CHANGE 
                await _auditLogService.LogPasswordChangeAsync(user.Id);

                // RE-SIGN IN USER
                await _signInManager.RefreshSignInAsync(user);

                TempData["SuccessMessage"] = "Your password has been changed successfully.";
                return RedirectToPage("/Index");
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return Page();
            }
        }

        private bool IsPasswordValid(string password)
        {
            if (password.Length < 12)
                return false;

            bool hasUpper = password.Any(char.IsUpper);
            bool hasLower = password.Any(char.IsLower);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSpecial = password.Any(ch => !char.IsLetterOrDigit(ch));

            return hasUpper && hasLower && hasDigit && hasSpecial;
        }
    }
}
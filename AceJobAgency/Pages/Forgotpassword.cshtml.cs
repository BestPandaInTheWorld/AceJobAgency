using AceJobAgency.Models;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace AceJobAgency.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly EmailOtpService _emailOtpService;
        private readonly AuditLogService _auditLogService;

        [BindProperty]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; }

        [BindProperty]
        public string ResetCode { get; set; }

        [BindProperty]
        [StringLength(100, ErrorMessage = "Password must be at least {2} characters long", MinimumLength = 12)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$",
            ErrorMessage = "Password must contain uppercase, lowercase, number and special character")]
        public string NewPassword { get; set; }

        [BindProperty]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; }

        // Session properties for storing reset code
        public string StoredResetCode
        {
            get => HttpContext.Session.GetString("ResetCode");
            set => HttpContext.Session.SetString("ResetCode", value ?? string.Empty);
        }

        public string ResetEmail
        {
            get => HttpContext.Session.GetString("ResetEmail");
            set => HttpContext.Session.SetString("ResetEmail", value ?? string.Empty);
        }

        public DateTime? ResetCodeExpiry
        {
            get
            {
                var expiryString = HttpContext.Session.GetString("ResetCodeExpiry");
                if (DateTime.TryParse(expiryString, out var expiry))
                    return expiry;
                return null;
            }
            set
            {
                if (value.HasValue)
                    HttpContext.Session.SetString("ResetCodeExpiry", value.Value.ToString("o"));
                else
                    HttpContext.Session.Remove("ResetCodeExpiry");
            }
        }

        public bool CodeVerified
        {
            get
            {
                var verified = HttpContext.Session.GetString("CodeVerified");
                return verified == "true";
            }
            set => HttpContext.Session.SetString("CodeVerified", value.ToString().ToLower());
        }

        public ForgotPasswordModel(
            UserManager<ApplicationUser> userManager,
            EmailOtpService emailOtpService,
            AuditLogService auditLogService)
        {
            _userManager = userManager;
            _emailOtpService = emailOtpService;
            _auditLogService = auditLogService;
        }

        public void OnGet()
        {
            // Just display the form
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // If no reset code provided, send reset email
            if (string.IsNullOrEmpty(ResetCode))
            {
                return await SendResetCodeAsync();
            }
            // If reset code provided but not verified, verify the code
            else if (!CodeVerified && !string.IsNullOrEmpty(ResetCode))
            {
                return await VerifyResetCodeAsync();
            }
            // If code verified and passwords provided, reset password
            else
            {
                return await ResetPasswordAsync();
            }
        }

        private async Task<IActionResult> SendResetCodeAsync()
        {
            // Clear ModelState errors for fields
            ModelState.Remove("ResetCode");
            ModelState.Remove("NewPassword");
            ModelState.Remove("ConfirmPassword");

            if (string.IsNullOrEmpty(Email))
            {
                ModelState.AddModelError(nameof(Email), "Email is required");
                return Page();
            }

            // Validate email format
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Email);

            // For security, always show success message even if user doesn't exist
            if (user == null)
            {
                await _auditLogService.LogActivityAsync("Unknown", "Password Reset Attempt", $"Reset requested for non-existent email: {Email}");
                TempData["SuccessMessage"] = "If an account exists with this email, you will receive a password reset code shortly.";
                return Page();
            }

            // Generate 6-digit reset code
            var code = new Random().Next(100000, 999999).ToString();
            var expiry = DateTime.UtcNow.AddMinutes(10);

            // Store in session
            StoredResetCode = code;
            ResetEmail = Email;
            ResetCodeExpiry = expiry;

            // Send email
            try
            {
                var userName = string.IsNullOrEmpty(user.FirstName) ? "User" : user.FirstName;
                await _emailOtpService.SendPasswordResetCodeAsync(user.Email, userName, code);

                await _auditLogService.LogActivityAsync(user.Id, "Password Reset Code Sent", $"Reset code sent to {user.Email}");

                TempData["SuccessMessage"] = $"A 6-digit reset code has been sent to {user.Email}. Please check your inbox.";
                ViewData["ShowResetForm"] = true;
                ViewData["UserEmail"] = _emailOtpService.MaskEmail(user.Email);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Failed to send reset email. Please try again.");
                await _auditLogService.LogActivityAsync(user.Id, "Password Reset Failed", $"Error: {ex.Message}");
                return Page();
            }

            return Page();
        }

        private async Task<IActionResult> VerifyResetCodeAsync()
        {
            // Clear ModelState errors for fields
            ModelState.Remove("Email");
            ModelState.Remove("NewPassword");
            ModelState.Remove("ConfirmPassword");

            var storedCode = StoredResetCode;
            var storedEmail = ResetEmail;
            var codeExpiry = ResetCodeExpiry;

            // Validate session data exists
            if (string.IsNullOrEmpty(storedCode) || string.IsNullOrEmpty(storedEmail))
            {
                ModelState.AddModelError(string.Empty, "Session expired. Please request a new reset code.");
                return Page();
            }

            // Validate code hasn't expired
            if (!codeExpiry.HasValue || codeExpiry.Value < DateTime.UtcNow)
            {
                ModelState.AddModelError(nameof(ResetCode), "Reset code has expired. Please request a new one.");
                HttpContext.Session.Remove("ResetCode");
                HttpContext.Session.Remove("ResetCodeExpiry");
                HttpContext.Session.Remove("CodeVerified");
                ViewData["ShowResetForm"] = true;
                return Page();
            }

            // Validate reset code
            if (string.IsNullOrEmpty(ResetCode))
            {
                ModelState.AddModelError(nameof(ResetCode), "Reset code is required.");
                ViewData["ShowResetForm"] = true;
                return Page();
            }

            // Validate code matches
            if (ResetCode != storedCode)
            {
                ModelState.AddModelError(nameof(ResetCode), "Invalid reset code. Please try again.");
                ViewData["ShowResetForm"] = true;
                return Page();
            }

            // Code is valid - mark as verified and show password form
            CodeVerified = true;
            ViewData["ShowResetForm"] = true;
            ViewData["ShowPasswordForm"] = true;
            ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);

            TempData["SuccessMessage"] = "Code verified! Please enter your new password.";

            var user = await _userManager.FindByEmailAsync(storedEmail);
            if (user != null)
            {
                await _auditLogService.LogActivityAsync(user.Id, "Reset Code Verified", "User verified reset code successfully");
            }

            return Page();
        }

        private async Task<IActionResult> ResetPasswordAsync()
        {
            // Clear ModelState errors for fields
            ModelState.Remove("Email");

            var storedCode = StoredResetCode;
            var storedEmail = ResetEmail;
            var codeExpiry = ResetCodeExpiry;
            var isCodeVerified = CodeVerified;

            // Validate session data exists
            if (string.IsNullOrEmpty(storedCode) || string.IsNullOrEmpty(storedEmail))
            {
                ModelState.AddModelError(string.Empty, "Session expired. Please request a new reset code.");
                return Page();
            }

            // Validate code is verified
            if (!isCodeVerified)
            {
                ModelState.AddModelError(string.Empty, "Please verify your reset code first.");
                ViewData["ShowResetForm"] = true;
                return Page();
            }

            // Validate code hasn't expired
            if (!codeExpiry.HasValue || codeExpiry.Value < DateTime.UtcNow)
            {
                ModelState.AddModelError(string.Empty, "Reset code has expired. Please request a new one.");
                HttpContext.Session.Remove("ResetCode");
                HttpContext.Session.Remove("ResetCodeExpiry");
                HttpContext.Session.Remove("CodeVerified");
                return Page();
            }

            // Validate new password
            if (string.IsNullOrEmpty(NewPassword))
            {
                ModelState.AddModelError(nameof(NewPassword), "New password is required.");
                ViewData["ShowResetForm"] = true;
                ViewData["ShowPasswordForm"] = true;
                ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);
                return Page();
            }

            if (string.IsNullOrEmpty(ConfirmPassword))
            {
                ModelState.AddModelError(nameof(ConfirmPassword), "Password confirmation is required.");
                ViewData["ShowResetForm"] = true;
                ViewData["ShowPasswordForm"] = true;
                ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);
                return Page();
            }

            if (NewPassword != ConfirmPassword)
            {
                ModelState.AddModelError(nameof(ConfirmPassword), "Passwords do not match.");
                ViewData["ShowResetForm"] = true;
                ViewData["ShowPasswordForm"] = true;
                ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);
                return Page();
            }

            // Validate ModelState for password requirements
            if (!ModelState.IsValid)
            {
                ViewData["ShowResetForm"] = true;
                ViewData["ShowPasswordForm"] = true;
                ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);
                return Page();
            }

            // Find user
            var user = await _userManager.FindByEmailAsync(storedEmail);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found.");
                return Page();
            }

            // Check password history (prevent reuse of last 2 passwords)
            var passwordHasher = new PasswordHasher<ApplicationUser>();

            if (!string.IsNullOrEmpty(user.PasswordHash))
            {
                var currentPasswordMatch = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, NewPassword);
                if (currentPasswordMatch == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError(nameof(NewPassword), "Cannot reuse your current password.");
                    ViewData["ShowResetForm"] = true;
                    ViewData["ShowPasswordForm"] = true;
                    ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);
                    return Page();
                }
            }

            if (!string.IsNullOrEmpty(user.PasswordHistory1))
            {
                var history1Match = passwordHasher.VerifyHashedPassword(user, user.PasswordHistory1, NewPassword);
                if (history1Match == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError(nameof(NewPassword), "Cannot reuse one of your last 2 passwords.");
                    ViewData["ShowResetForm"] = true;
                    ViewData["ShowPasswordForm"] = true;
                    ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);
                    return Page();
                }
            }

            if (!string.IsNullOrEmpty(user.PasswordHistory2))
            {
                var history2Match = passwordHasher.VerifyHashedPassword(user, user.PasswordHistory2, NewPassword);
                if (history2Match == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError(nameof(NewPassword), "Cannot reuse one of your last 2 passwords.");
                    ViewData["ShowResetForm"] = true;
                    ViewData["ShowPasswordForm"] = true;
                    ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);
                    return Page();
                }
            }

            // Update password history
            user.PasswordHistory2 = user.PasswordHistory1;
            user.PasswordHistory1 = user.PasswordHash;

            // Reset password
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, NewPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                ViewData["ShowResetForm"] = true;
                ViewData["ShowPasswordForm"] = true;
                ViewData["UserEmail"] = _emailOtpService.MaskEmail(storedEmail);
                return Page();
            }

            // Update password change date
            user.LastPasswordChangeDate = DateTime.UtcNow;
            user.NextPasswordChangeDate = DateTime.UtcNow.AddDays(90);
            await _userManager.UpdateAsync(user);

            // Clear session
            HttpContext.Session.Remove("ResetCode");
            HttpContext.Session.Remove("ResetEmail");
            HttpContext.Session.Remove("ResetCodeExpiry");
            HttpContext.Session.Remove("CodeVerified");

            await _auditLogService.LogActivityAsync(user.Id, "Password Reset Success", "Password reset via email code");

            TempData["SuccessMessage"] = "Password reset successful! You can now login with your new password.";
            return RedirectToPage("/Login");
        }
    }
}
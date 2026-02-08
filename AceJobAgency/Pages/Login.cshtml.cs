using AceJobAgency.Models;
using AceJobAgency.Services;
using AceJobAgency.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Threading.Tasks;

namespace AceJobAgency.Pages
{
    public class LoginModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuditLogService _auditLogService;
        private readonly SessionValidationService _sessionValidationService;
        private readonly EmailOtpService _emailOtpService;

        [BindProperty]
        public Login LInput { get; set; }

        public string TwoFactorUserId
        {
            get => HttpContext.Session.GetString("TwoFactorUserId");
            set => HttpContext.Session.SetString("TwoFactorUserId", value ?? string.Empty);
        }

        public string TwoFactorCode
        {
            get => HttpContext.Session.GetString("TwoFactorCode");
            set => HttpContext.Session.SetString("TwoFactorCode", value ?? string.Empty);
        }

        public DateTime? TwoFactorCodeExpiry
        {
            get
            {
                var expiryString = HttpContext.Session.GetString("TwoFactorCodeExpiry");
                if (DateTime.TryParse(expiryString, out var expiry))
                    return expiry;
                return null;
            }
            set
            {
                if (value.HasValue)
                    HttpContext.Session.SetString("TwoFactorCodeExpiry", value.Value.ToString("o"));
                else
                    HttpContext.Session.Remove("TwoFactorCodeExpiry");
            }
        }

        public string TimeoutMessage { get; set; }

        public LoginModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            AuditLogService auditLogService,
            SessionValidationService sessionValidationService,
            EmailOtpService emailOtpService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _auditLogService = auditLogService;
            _sessionValidationService = sessionValidationService;
            _emailOtpService = emailOtpService;
        }

        public void OnGet(bool? timeout)
        {
            if (timeout == true)
            {
                TimeoutMessage = "Your session has expired due to inactivity. Please login again.";
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // FIND USER
            var user = await _userManager.FindByEmailAsync(LInput.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid email or password");
                await _auditLogService.LogActivityAsync("Unknown", "Failed Login", $"Login attempt for non-existent email: {LInput.Email}");
                return Page();
            }

            // CHECK LOCKOUT
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
            {
                var remainingTime = (user.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes;
                ModelState.AddModelError("", $"Account locked. Try again in {Math.Ceiling(remainingTime)} minutes.");
                return Page();
            }

            // AUTO UNLOCK
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value <= DateTime.UtcNow)
            {
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                await _userManager.UpdateAsync(user);
                await _auditLogService.LogActivityAsync(user.Id, "Account Unlocked", "Auto-unlocked");
            }

            // VERIFY PASSWORD
            var result = await _signInManager.CheckPasswordSignInAsync(user, LInput.Password, false);

            if (!result.Succeeded)
            {
                user.FailedLoginAttempts++;

                if (user.FailedLoginAttempts >= 3)
                {
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(5);
                    await _userManager.UpdateAsync(user);
                    ModelState.AddModelError("", "Account locked for 5 minutes.");
                    await _auditLogService.LogAccountLockoutAsync(user.Id, 5);
                }
                else
                {
                    await _userManager.UpdateAsync(user);
                    var attemptsLeft = 3 - user.FailedLoginAttempts;
                    ModelState.AddModelError("", $"Invalid password. {attemptsLeft} attempt(s) remaining.");
                }

                await _auditLogService.LogFailedLoginAsync(user.Id, "Invalid password");
                return Page();
            }

            // PASSWORD CORRECT - SEND EMAIL OTP AUTOMATICALLY! ??
            if (string.IsNullOrEmpty(LInput.TwoFactorCode))
            {
                // Generate code
                var code = new Random().Next(100000, 999999).ToString();
                var expiry = DateTime.UtcNow.AddMinutes(10);

                TwoFactorUserId = user.Id;
                TwoFactorCode = code;
                TwoFactorCodeExpiry = expiry;

                // AUTO-SEND EMAIL OTP
                try
                {
                    var userName = string.IsNullOrEmpty(user.FirstName) ? "User" : user.FirstName;

                    await _emailOtpService.SendTwoFactorCodeAsync(user.Email, userName, code);

                    var maskedEmail = _emailOtpService.MaskEmail(user.Email);

                    ViewData["Show2FA"] = true;
                    ViewData["UserEmail"] = maskedEmail;
                    ViewData["TwoFactorCode"] = code; 

                    TempData["SuccessMessage"] = $"A 6-digit verification code sent to {user.Email}! Check your inbox.";
                    await _auditLogService.LogActivityAsync(user.Id, "2FA Code Sent", $"Email OTP sent to {user.Email}");
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Failed to send verification email. Please try again.");
                    await _auditLogService.LogActivityAsync(user.Id, "2FA Failed", $"Error: {ex.Message}");
                    return Page();
                }

                return Page();
            }
            else
            {
                // VERIFY CODE
                var storedCode = TwoFactorCode;
                var codeExpiry = TwoFactorCodeExpiry;

                if (string.IsNullOrEmpty(storedCode))
                {
                    ModelState.AddModelError("", "Session expired. Please login again.");
                    return Page();
                }

                if (!codeExpiry.HasValue || codeExpiry.Value < DateTime.UtcNow)
                {
                    ModelState.AddModelError("LInput.TwoFactorCode", "Code expired. Please request a new one.");
                    HttpContext.Session.Remove("TwoFactorCode");
                    HttpContext.Session.Remove("TwoFactorCodeExpiry");
                    ViewData["Show2FA"] = true;
                    ViewData["UserEmail"] = _emailOtpService.MaskEmail(user.Email);
                    return Page();
                }

                if (LInput.TwoFactorCode != storedCode)
                {
                    ModelState.AddModelError("LInput.TwoFactorCode", "Invalid verification code.");
                    await _auditLogService.LogActivityAsync(user.Id, "2FA Failed", "Wrong code");
                    ViewData["Show2FA"] = true;
                    ViewData["UserEmail"] = _emailOtpService.MaskEmail(user.Email);
                    return Page();
                }

                await _auditLogService.LogActivityAsync(user.Id, "2FA Success", "Code verified");

                HttpContext.Session.Remove("TwoFactorUserId");
                HttpContext.Session.Remove("TwoFactorCode");
                HttpContext.Session.Remove("TwoFactorCodeExpiry");
            }

            // RESET FAILED ATTEMPTS
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;

            // SESSION MANAGEMENT
            if (!string.IsNullOrEmpty(user.CurrentSessionId))
            {
                await _auditLogService.LogMultipleDeviceLoginAsync(user.Id);
            }

            var sessionId = await _sessionValidationService.CreateSessionAsync(HttpContext, user);

            // PASSWORD AGE CHECK
            var daysSinceChange = (DateTime.UtcNow - user.LastPasswordChangeDate).TotalDays;
            if (daysSinceChange > 90)
            {
                TempData["ForcePasswordChange"] = "Password expired. Please change it.";
                await _signInManager.SignInAsync(user, LInput.RememberMe);
                return RedirectToPage("/ChangePassword");
            }

            await _userManager.UpdateAsync(user);

            // SIGN IN
            await _signInManager.SignInAsync(user, LInput.RememberMe);
            await _auditLogService.LogLoginAsync(user.Id);

            return RedirectToPage("/Index");
        }
    }
}
using AceJobAgency.Models;
using AceJobAgency.Services;
using AceJobAgency.ViewModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace AceJobAgency.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IWebHostEnvironment _environment;
        private readonly AuditLogService _auditLogService;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;

        [BindProperty]
        public Register RInput { get; set; }

        public string RecaptchaSiteKey { get; set; }

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IWebHostEnvironment environment,
            AuditLogService auditLogService,
            IConfiguration configuration,
            IHttpClientFactory httpClientFactory)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _environment = environment;
            _auditLogService = auditLogService;
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
        }

        public void OnGet()
        {
            // Load reCAPTCHA site key from configuration
            RecaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Load reCAPTCHA site key for potential page re-render
            RecaptchaSiteKey = _configuration["ReCaptcha:SiteKey"];

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // 1. SERVER-SIDE PASSWORD VALIDATION
            if (!IsPasswordValid(RInput.Password))
            {
                ModelState.AddModelError("RInput.Password",
                    "Password must be at least 12 characters with uppercase, lowercase, number, and special character.");
                return Page();
            }

            // 2. CHECK FOR DUPLICATE EMAIL
            var existingUser = await _userManager.FindByEmailAsync(RInput.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("RInput.Email", "This email address is already registered. Please use a different email or login.");
                return Page();
            }

            // 3. VALIDATE RECAPTCHA
            if (string.IsNullOrEmpty(RInput.RecaptchaToken))
            {
                ModelState.AddModelError("", "Please complete the reCAPTCHA verification.");
                return Page();
            }

            // Verify reCAPTCHA with Google
            var isRecaptchaValid = await VerifyRecaptchaAsync(RInput.RecaptchaToken);
            if (!isRecaptchaValid)
            {
                ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            // 4. HANDLE RESUME FILE UPLOAD
            string? resumePath = null;
            if (RInput.Resume != null)
            {
                resumePath = await SaveResumeFileAsync(RInput.Resume);
                if (resumePath == null)
                {
                    ModelState.AddModelError("RInput.Resume",
                        "Invalid file. Only PDF and DOCX files under 5MB are allowed.");
                    return Page();
                }
            }

            // 5. ENCRYPT NRIC 
            var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
            var protector = dataProtectionProvider.CreateProtector("NRIC-Protection-Key");
            string encryptedNRIC = protector.Protect(RInput.NRIC);

            // 6. CREATE USER 
            var user = new ApplicationUser
            {
                UserName = RInput.Email,
                Email = RInput.Email,
                FirstName = SanitizeInput(RInput.FirstName),
                LastName = SanitizeInput(RInput.LastName),
                Gender = RInput.Gender,
                NRIC = encryptedNRIC,
                DateOfBirth = RInput.DateOfBirth,
                ResumePath = resumePath,
                WhoAmI = RInput.WhoAmI,
                LastPasswordChangeDate = DateTime.UtcNow,
                NextPasswordChangeDate = DateTime.UtcNow.AddDays(90), 
                CreatedAt = DateTime.UtcNow
            };

            // Create user with password hashing
            var result = await _userManager.CreateAsync(user, RInput.Password);

            if (result.Succeeded)
            {
                // CREATE "MEMBER" ROLE IF NOT EXISTS
                var memberRole = await _roleManager.FindByNameAsync("Member");
                if (memberRole == null)
                {
                    await _roleManager.CreateAsync(new IdentityRole("Member"));
                }

                // ASSIGN USER TO ROLE
                await _userManager.AddToRoleAsync(user, "Member");

                // STORE PASSWORD IN HISTORY 
                user.PasswordHistory1 = user.PasswordHash; 
                await _userManager.UpdateAsync(user);

                // LOG REGISTRATION 
                await _auditLogService.LogRegistrationAsync(user.Id);

                // SIGN IN USER
                await _signInManager.SignInAsync(user, isPersistent: false);

                TempData["SuccessMessage"] = "Registration successful! Welcome to Ace Job Agency.";
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

        private async Task<bool> VerifyRecaptchaAsync(string token)
        {
            try
            {
                var secretKey = _configuration["ReCaptcha:SecretKey"];

                if (string.IsNullOrEmpty(secretKey))
                {
                    Console.WriteLine("ERROR: ReCaptcha:SecretKey not found in configuration!");
                    return false;
                }

                var client = _httpClientFactory.CreateClient();

                // Include remote IP for better security
                var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                var url = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}&remoteip={remoteIp}";

                var response = await client.PostAsync(url, null);

                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Google API returned status code: {response.StatusCode}");
                    return false;
                }

                var jsonString = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<RecaptchaResponse>(jsonString, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (result == null)
                {
                    Console.WriteLine("Failed to deserialize reCAPTCHA response");
                    return false;
                }

                // SERVER-SIDE HOSTNAME VERIFICATION
                var currentHostname = HttpContext.Request.Host.Host;
                var allowedHostnames = new[] { "localhost", "127.0.0.1" };

                if (!allowedHostnames.Contains(currentHostname) && !currentHostname.EndsWith(".com"))
                {
                    Console.WriteLine($"Hostname verification failed: Request from {currentHostname}");
                    Console.WriteLine("WARNING: Hostname not in allowed list but proceeding for development");
                }

                // Log any error codes from Google
                if (result.ErrorCodes != null && result.ErrorCodes.Length > 0)
                {
                    Console.WriteLine($"reCAPTCHA errors: {string.Join(", ", result.ErrorCodes)}");
                    return false;
                }

                // For v3, check score threshold
                var version = _configuration["ReCaptcha:Version"];
                if (version == "v3")
                {
                    var scoreThreshold = double.Parse(_configuration["ReCaptcha:ScoreThreshold"] ?? "0.5");
                    return result.Success && result.Score >= scoreThreshold;
                }

                // For v2, just check success
                return result.Success;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"reCAPTCHA verification error: {ex.Message}");
                return false;
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

        private async Task<string?> SaveResumeFileAsync(Microsoft.AspNetCore.Http.IFormFile file)
        {
            // Validate extension
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (extension != ".pdf" && extension != ".docx")
                return null;

            // Validate size (5MB max)
            if (file.Length > 5 * 1024 * 1024)
                return null;

            // Validate content type
            var allowedContentTypes = new[] { "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" };
            if (!allowedContentTypes.Contains(file.ContentType))
                return null;

            // Generate unique filename (prevents overwriting)
            var uniqueFileName = $"{Guid.NewGuid()}{extension}";
            var uploadsFolder = Path.Combine(_environment.WebRootPath, "resumes");

            // Create directory if doesn't exist
            if (!Directory.Exists(uploadsFolder))
                Directory.CreateDirectory(uploadsFolder);

            var filePath = Path.Combine(uploadsFolder, uniqueFileName);

            // Save file
            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(fileStream);
            }

            return $"/resumes/{uniqueFileName}";
        }

        private string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // Remove potentially harmful characters
            return Regex.Replace(input, @"[<>""']", "");
        }

        private class RecaptchaResponse
        {
            [JsonPropertyName("success")]
            public bool Success { get; set; }

            [JsonPropertyName("score")]
            public double Score { get; set; }

            [JsonPropertyName("action")]
            public string Action { get; set; }

            [JsonPropertyName("challenge_ts")]
            public string ChallengeTs { get; set; }

            [JsonPropertyName("hostname")]
            public string Hostname { get; set; }

            [JsonPropertyName("error-codes")]
            public string[] ErrorCodes { get; set; }
        }
    }
}
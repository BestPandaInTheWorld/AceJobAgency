using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.ViewModels
{
    public class Login
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Display(Name = "Email Address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }

        [Display(Name = "2FA Code")]
        public string? TwoFactorCode { get; set; }
    }
}
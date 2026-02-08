using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [MaxLength(100)]
        [PersonalData]
        public string FirstName { get; set; }

        [Required]
        [MaxLength(100)]
        [PersonalData]
        public string LastName { get; set; }

        [Required]
        [MaxLength(10)]
        [PersonalData]
        public string Gender { get; set; }

        // NRIC
        [Required]
        [PersonalData]
        public string NRIC { get; set; }

        [Required]
        [PersonalData]
        public DateTime DateOfBirth { get; set; }

        // Resume file path
        [MaxLength(500)]
        public string? ResumePath { get; set; }

        // Allows special characters
        [PersonalData]
        public string? WhoAmI { get; set; }

        // Failed login tracking
        public int FailedLoginAttempts { get; set; } = 0;

        // Lockout end time
        public DateTime? LockoutEnd { get; set; }

        // Password history
        public string? PasswordHistory1 { get; set; }
        public string? PasswordHistory2 { get; set; }

        // Password age tracking
        public DateTime LastPasswordChangeDate { get; set; } = DateTime.UtcNow;
        public DateTime? NextPasswordChangeDate { get; set; }

        // Session tracking
        public string? CurrentSessionId { get; set; }

        // Account creation timestamp
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
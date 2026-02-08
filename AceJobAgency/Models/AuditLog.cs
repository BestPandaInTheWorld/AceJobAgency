using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AceJobAgency.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [ForeignKey("UserId")]
        public ApplicationUser User { get; set; }

        [Required]
        [MaxLength(100)]
        public string Activity { get; set; }

        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        [MaxLength(45)]
        public string? IPAddress { get; set; }

        [MaxLength(500)]
        public string? Details { get; set; }

        [MaxLength(200)]
        public string? UserAgent { get; set; }
    }
}
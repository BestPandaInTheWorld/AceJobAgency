using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace AceJobAgency.Services
{
    public class EmailOtpService
    {
        private readonly ILogger<EmailOtpService> _logger;

        private const string GMAIL_ADDRESS = "ljingda222@gmail.com"; 
        private const string GMAIL_APP_PASSWORD = "omuq ykwz rtgh ydxm"; 

        private const string SMTP_HOST = "smtp.gmail.com";
        private const int SMTP_PORT = 587;

        public EmailOtpService(ILogger<EmailOtpService> logger)
        {
            _logger = logger;
        }

        // Sends OTP code via email
        public Task SendTwoFactorCodeAsync(string recipientEmail, string recipientName, string code)
        {
            try
            {
                // Create email message
                using var smtpClient = new SmtpClient(SMTP_HOST, SMTP_PORT)
                {
                    EnableSsl = true,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(GMAIL_ADDRESS, GMAIL_APP_PASSWORD.Replace(" ", ""))
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(GMAIL_ADDRESS, "Ace Job Agency"),
                    Subject = "Your Login Verification Code",
                    IsBodyHtml = true,
                    Body = $@"
                        <html>
                        <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
                            <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
                                <div style='background-color: #198754; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;'>
                                    <h1 style='margin: 0; font-size: 24px;'>🔐 Verification Code</h1>
                                </div>
                                <div style='background-color: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; border: 1px solid #ddd;'>
                                    <p style='font-size: 16px;'>Hello <strong>{recipientName}</strong>,</p>
                                    <p style='font-size: 16px;'>You are attempting to log in to your Ace Job Agency account. Use the verification code below:</p>
                                    
                                    <div style='background-color: white; border: 3px solid #198754; padding: 25px; text-align: center; margin: 25px 0; border-radius: 8px;'>
                                        <h2 style='color: #198754; font-size: 42px; letter-spacing: 10px; margin: 0; font-family: Courier New, monospace; font-weight: bold;'>{code}</h2>
                                    </div>
                                    
                                    <p style='color: #666; font-size: 14px; background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; border-radius: 4px;'>
                                        <strong>⏱️ This code will expire in 10 minutes.</strong>
                                    </p>
                                    
                                    <hr style='border: none; border-top: 1px solid #ddd; margin: 25px 0;'>
                                    
                                    <p style='color: #666; font-size: 13px; background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; border-radius: 4px;'>
                                        ⚠️ <strong>Security Note:</strong> If you didn't request this code, please ignore this email and ensure your account is secure.
                                    </p>
                                    
                                    <p style='color: #999; font-size: 12px; margin-top: 30px; text-align: center;'>
                                        Best regards,<br>
                                        <strong>Ace Job Agency Security Team</strong>
                                    </p>
                                </div>
                            </div>
                        </body>
                        </html>
                    "
                };

                mailMessage.To.Add(new MailAddress(recipientEmail, recipientName));

                // SEND IT!
                smtpClient.Send(mailMessage);

                // Success notification in console
                Console.WriteLine("╔════════════════════════════════════════════════════════╗");
                Console.WriteLine("║            ✓ EMAIL OTP SENT SUCCESSFULLY!              ║");
                Console.WriteLine("╠════════════════════════════════════════════════════════╣");
                Console.WriteLine($"║  To: {recipientEmail.PadRight(48)} ║");
                Console.WriteLine($"║  Name: {recipientName.PadRight(46)} ║");
                Console.WriteLine($"║  Code: {code.PadRight(46)} ║");
                Console.WriteLine($"║  ✉️  Check email inbox (and spam folder)!{"".PadRight(14)} ║");
                Console.WriteLine("╚════════════════════════════════════════════════════════╝");

                _logger.LogInformation($"[EMAIL OTP] Sent code {code} to {recipientEmail}");
            }
            catch (SmtpException ex)
            {
                Console.WriteLine("╔════════════════════════════════════════════════════════╗");
                Console.WriteLine("║                   ❌ SMTP ERROR!                       ║");
                Console.WriteLine("╠════════════════════════════════════════════════════════╣");
                Console.WriteLine($"║  Error: {ex.Message.PadRight(45)} ║");
                Console.WriteLine("╠════════════════════════════════════════════════════════╣");
                Console.WriteLine("║  📋 TROUBLESHOOTING:                                   ║");
                Console.WriteLine("║  1. Check GMAIL_ADDRESS is correct                     ║");
                Console.WriteLine("║  2. Enable 2-Step Verification on Google               ║");
                Console.WriteLine("║  3. Generate App Password at:                          ║");
                Console.WriteLine("║     https://myaccount.google.com/apppasswords          ║");
                Console.WriteLine("║  4. Copy App Password to GMAIL_APP_PASSWORD            ║");
                Console.WriteLine("║  5. Restart your application                           ║");
                Console.WriteLine("╚════════════════════════════════════════════════════════╝");

                _logger.LogError($"[EMAIL OTP] SMTP failed: {ex.Message}");

                // Show code in console as fallback
                LogToConsole(recipientEmail, code);

                throw new Exception($"Failed to send email: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Unexpected error: {ex.Message}");
                _logger.LogError($"[EMAIL OTP] Error: {ex.Message}");
                LogToConsole(recipientEmail, code);
                throw;
            }

            return Task.CompletedTask;
        }

        public Task SendPasswordResetCodeAsync(string recipientEmail, string recipientName, string code)
        {
            try
            {
                using var smtpClient = new SmtpClient(SMTP_HOST, SMTP_PORT)
                {
                    EnableSsl = true,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(GMAIL_ADDRESS, GMAIL_APP_PASSWORD.Replace(" ", ""))
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(GMAIL_ADDRESS, "Ace Job Agency"),
                    Subject = "Password Reset Verification Code",
                    IsBodyHtml = true,
                    Body = $@"
                        <html>
                        <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
                            <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
                                <div style='background-color: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;'>
                                    <h1 style='margin: 0; font-size: 24px;'>🔑 Password Reset Code</h1>
                                </div>
                                <div style='background-color: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; border: 1px solid #ddd;'>
                                    <p style='font-size: 16px;'>Hello <strong>{recipientName}</strong>,</p>
                                    <p style='font-size: 16px;'>You requested to reset your password. Use the code below:</p>
                                    
                                    <div style='background-color: white; border: 3px solid #dc3545; padding: 25px; text-align: center; margin: 25px 0; border-radius: 8px;'>
                                        <h2 style='color: #dc3545; font-size: 42px; letter-spacing: 10px; margin: 0; font-family: Courier New, monospace; font-weight: bold;'>{code}</h2>
                                    </div>
                                    
                                    <p style='color: #666; font-size: 14px; background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; border-radius: 4px;'>
                                        <strong>⏱️ This code will expire in 10 minutes.</strong>
                                    </p>
                                    
                                    <hr style='border: none; border-top: 1px solid #ddd; margin: 25px 0;'>
                                    
                                    <p style='color: #666; font-size: 13px; background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; border-radius: 4px;'>
                                        ⚠️ <strong>Security Warning:</strong> If you didn't request this, please secure your account immediately!
                                    </p>
                                </div>
                            </div>
                        </body>
                        </html>
                    "
                };

                mailMessage.To.Add(new MailAddress(recipientEmail, recipientName));
                smtpClient.Send(mailMessage);

                Console.WriteLine($"✓ Password reset code sent to {recipientEmail}");
                _logger.LogInformation($"[EMAIL OTP] Password reset code {code} sent to {recipientEmail}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"[EMAIL OTP] Password reset failed: {ex.Message}");
                LogToConsole(recipientEmail, code);
                throw;
            }

            return Task.CompletedTask;
        }

        private void LogToConsole(string email, string code)
        {
            Console.WriteLine("╔════════════════════════════════════════════════════════╗");
            Console.WriteLine("║       OTP CODE (Console Fallback)                      ║");
            Console.WriteLine("╠════════════════════════════════════════════════════════╣");
            Console.WriteLine($"║  Email: {email.PadRight(45)} ║");
            Console.WriteLine($"║  Code: {code.PadRight(46)} ║");
            Console.WriteLine($"║  Expires: 10 minutes{"".PadRight(34)} ║");
            Console.WriteLine("╚════════════════════════════════════════════════════════╝");
        }

        public string MaskEmail(string email)
        {
            if (string.IsNullOrEmpty(email) || !email.Contains("@"))
                return "***@***.com";

            var parts = email.Split('@');
            var localPart = parts[0];
            var domain = parts[1];

            if (localPart.Length <= 2)
                return $"**@{domain}";

            var maskedLocal = $"{localPart[0]}***{localPart[localPart.Length - 1]}";
            return $"{maskedLocal}@{domain}";
        }
    }
}
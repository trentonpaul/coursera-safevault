using System.Net.Mail;
using System.Text.RegularExpressions;

namespace SafeVault.Helpers
{
    public static class ValidationUtils
    {
        /// <summary>
        /// Validates password complexity: minimum 8 chars, with uppercase, lowercase, and digit.
        /// </summary>
        public static bool IsValidPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
                return false;

            return password.Any(char.IsUpper) &&
                   password.Any(char.IsLower) &&
                   password.Any(char.IsDigit);
        }

        /// <summary>
        /// Validates email format and returns cleaned address.
        /// </summary>
        public static string SanitizeEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return string.Empty;

            try
            {
                var addr = new MailAddress(email.Trim());
                return addr.Address;
            }
            catch
            {
                throw new FormatException("Invalid email format.");
            }
        }
    }
}
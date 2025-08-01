using System;
using System.Text.RegularExpressions;

namespace SafeVault.Helpers
{
    public static class InputSanitizer
    {
        /// <summary>
        /// Strips non-alphanumeric characters except underscore for safe usernames.
        /// </summary>
        public static string SanitizeUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return string.Empty;

            username = SanitizeInput(username);

            return Regex.Replace(username, @"[^\w]", string.Empty);
        }

        /// <summary>
        /// Validates and returns a clean email if valid, otherwise throws.
        /// </summary>
        public static string SanitizeEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return string.Empty;

            email = SanitizeInput(email);

            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address;
            }
            catch
            {
                throw new FormatException("Invalid email format.");
            }
        }

        /// <summary>
        /// Sanitizes input by removing script tags to prevent XSS.
        /// </summary>
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove script tags to prevent XSS
            input = StripScriptTags(input);

            return input;
        }

        /// <summary>
        /// Removes potential script tags to defend against basic XSS attempts.
        /// </summary>
        public static string StripScriptTags(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            return Regex.Replace(input, @"<script.*?>.*?</script>", string.Empty, RegexOptions.IgnoreCase);
        }
    }
}

using BCrypt.Net;

namespace SafeVault.Helpers
{
    public class PasswordTools
    {
        public static string HashPassword(string password)
        {
            // Secure hash using Bcrypt
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public static bool VerifyPassword(string password, string hashedPassword)
        {
            // Verify the password against the hashed password
            return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
        }

        /// <summary>
        /// Validates if the password meets security requirements.
        /// /// At least 8 characters long, contains uppercase, lowercase, and numeric characters.
        /// </summary>
        public static bool IsValidPassword(string password)
        {
            // At least 8 characters, one uppercase, one lowercase, one digit
            if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
                return false;

            bool hasUpper = false, hasLower = false, hasDigit = false;

            foreach (char c in password)
            {
                if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsLower(c)) hasLower = true;
                else if (char.IsDigit(c)) hasDigit = true;

                if (hasUpper && hasLower && hasDigit)
                    return true;
            }

            return false;
        }
    }
}
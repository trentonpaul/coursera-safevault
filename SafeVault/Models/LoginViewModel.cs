using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Username is required.")]
        [StringLength(100, ErrorMessage = "Username must not exceed 100 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9_.-]+$", 
            ErrorMessage = "Username can only contain letters, digits, underscores, hyphens, or periods.")]
        public required string Username { get; set; }
        
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [StringLength(255, MinimumLength = 8,
            ErrorMessage = "Password must be at least 8 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$",
            ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, and one number.")]
        public required string Password { get; set; }
    }
}
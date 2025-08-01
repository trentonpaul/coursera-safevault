using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SafeVault.Models
{
    public class User
    {
        [Key]
        public int UserID { get; set; }

        [Required(ErrorMessage = "Username is required.")]
        [StringLength(100)]
        [RegularExpression(@"^\w+$", ErrorMessage = "Username can only contain letters, numbers, and underscores.")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        [StringLength(100)]
        public string Email { get; set; }

        [NotMapped]
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [StringLength(255)]
        public string PasswordHash { get; set; }

        [Required(ErrorMessage = "Role is required.")]
        [StringLength(100)]
        public string Role { get; set; }
    }
}
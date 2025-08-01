using Microsoft.AspNetCore.Mvc;
using System.Data;
using MySql.Data.MySqlClient;
using SafeVault.Helpers;
using SafeVault.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using SafeVault.Services;
using System.IdentityModel.Tokens.Jwt;

namespace SafeVault.Controllers
{
    public class UserController : Controller
    {
        private readonly string _connectionString;
        private readonly ITokenService _tokenService;
        private readonly int _jwtMinutes;
        public UserController(IConfiguration configuration, ITokenService tokenService)
        {
            var connSection = configuration.GetSection("ConnectionStrings");
            _connectionString = connSection["SafeVaultDb"]
                ?? throw new InvalidOperationException("Connection string 'SafeVaultDb' not found.");

            _tokenService = tokenService;

            var jwtMinutesValue = configuration.GetSection("Jwt:Minutes").Value;
            _jwtMinutes = int.TryParse(jwtMinutesValue, out int minutes) && minutes > 0
                ? minutes
                : 60;
        }



        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Register(string username, string email, string password, string role)
        {
            try
            {
                // Sanitize inputs
                var cleanUsername = InputSanitizer.SanitizeUsername(username);
                var cleanEmail = InputSanitizer.SanitizeEmail(email);

                // Validate that inputs are not empty or malformed
                if (string.IsNullOrWhiteSpace(cleanUsername) || string.IsNullOrWhiteSpace(cleanEmail))
                {
                    Console.WriteLine("Username or email is empty.");
                    ModelState.AddModelError("", "Username and email are required.");
                    return View("Register");
                }

                if (!PasswordTools.IsValidPassword(password))
                {
                    Console.WriteLine("Invalid password format.");
                    ModelState.AddModelError("", "Password must be at least 8 characters long and contain uppercase, lowercase, and numeric characters.");
                    return View("Register");
                }

                var passwordHash = PasswordTools.HashPassword(password);

                // Insert into database using parameterized query
                using var conn = new MySqlConnection(_connectionString);
                conn.Open();
                using var cmd = new MySqlCommand("INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@Username, @Email, @PasswordHash, @Role)", conn);
                cmd.Parameters.AddWithValue("@Username", cleanUsername);
                cmd.Parameters.AddWithValue("@Email", cleanEmail);
                cmd.Parameters.AddWithValue("@PasswordHash", passwordHash);
                cmd.Parameters.AddWithValue("@Role", role);
                cmd.ExecuteNonQuery();

                // return View("Register");

                return RedirectToAction("Success");
            }
            catch (Exception ex)
            {
                // Log exception and return friendly error
                Console.WriteLine(ex);
                ModelState.AddModelError("", "Something went wrong. Please try again.");
                return View();
            }
        }

        public IActionResult Success()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            try
            {
                var cleanUsername = InputSanitizer.SanitizeUsername(username);

                if (string.IsNullOrWhiteSpace(cleanUsername) || string.IsNullOrWhiteSpace(password))
                {
                    ModelState.AddModelError("", "Username and password are required.");
                    return View();
                }

                using var conn = new MySqlConnection(_connectionString);
                conn.Open();
                using var cmd = new MySqlCommand("SELECT PasswordHash, Role FROM Users WHERE Username = @Username", conn);
                cmd.Parameters.AddWithValue("@Username", cleanUsername);

                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    ModelState.AddModelError("", "Invalid username or password.");
                    return View();
                }

                var passwordHash = reader.GetString("PasswordHash");
                var role = reader.GetString("Role");

                if (!PasswordTools.VerifyPassword(password, passwordHash))
                {
                    ModelState.AddModelError("", "Invalid username or password.");
                    return View();
                }

                // Add role to JWT role
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, cleanUsername),
                    new Claim(ClaimTypes.Name, cleanUsername),
                    new Claim(ClaimTypes.Role, role),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                var token = _tokenService.GenerateToken(claims);

                Response.Cookies.Append("AuthToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(_jwtMinutes)
                });

                return RedirectToAction("Success");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                ModelState.AddModelError("", "Something went wrong. Please try again.");
                return View();
            }
        }

        [HttpGet]
        [Authorize(Policy = "AdminOnly")]
        public IActionResult Admin()
        {
            // Writing specifcally for NUnit testing because it can't simulate auth middleware
            if (!User.IsInRole("Admin"))
            {
                return Forbid();
            }
            return View();
        }

        [HttpGet]
        [Authorize(Policy = "UserOnly")]
        public IActionResult UserOnly()
        {
            // Writing specifcally for NUnit testing because it can't simulate auth middleware
            if (!User.IsInRole("User"))
            {
                return Forbid();
            }
            return View();
        }
    }
}
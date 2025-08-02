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
using Microsoft.AspNetCore.Identity;

namespace SafeVault.Controllers
{
    public class UserController : Controller
    {
        private readonly string _connectionString;
        private readonly ITokenService _tokenService;
        private readonly int _jwtMinutes;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public UserController(IConfiguration configuration, ITokenService tokenService, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            var connSection = configuration.GetSection("ConnectionStrings");
            _connectionString = connSection["SafeVaultDb"]
                ?? throw new InvalidOperationException("Connection string 'SafeVaultDb' not found.");

            _tokenService = tokenService;

            var jwtMinutesValue = configuration.GetSection("Jwt:Minutes").Value;
            _jwtMinutes = int.TryParse(jwtMinutesValue, out int minutes) && minutes > 0
                ? minutes
                : 60;

            _userManager = userManager;
            _signInManager = signInManager;

        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, model.Role);

                var roles = await _userManager.GetRolesAsync(user);
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                foreach (var r in roles)
                    claims.Add(new Claim(ClaimTypes.Role, r));

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


            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            return View(model);
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
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                ModelState.AddModelError("", "Invalid credentials.");
                return View();
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

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

        [HttpGet]
        [Authorize(Policy = "AdminOnly")]
        public IActionResult Admin()
        {
            // Writing specifcally for NUnit testing because it can't simulate auth middleware
            if (!User.IsInRole("ADMIN"))
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
            if (!User.IsInRole("USER"))
            {
                return Forbid();
            }
            return View();
        }
    }
}
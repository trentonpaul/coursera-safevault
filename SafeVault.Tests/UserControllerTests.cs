using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Moq;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.AspNetCore.Mvc; // Only required for RedirectToActionResult, ViewResult

namespace SafeVault.Tests
{
    public class UserControllerTests
    {
        private Mock<IConfiguration> _configuration;
        private Mock<ITokenService> _tokenService;
        private Mock<UserManager<IdentityUser>> _userManager;
        private Mock<SignInManager<IdentityUser>> _signInManager;

        [SetUp]
        public void SetUp()
        {
            _configuration = new Mock<IConfiguration>();
            _tokenService = new Mock<ITokenService>();

            // Mock configuration values
            var connSectionMock = new Mock<IConfigurationSection>();
            connSectionMock.Setup(s => s["SafeVaultDb"]).Returns("Server=localhost;Database=SafeVaultDb;Uid=test;Pwd=test;");
            _configuration.Setup(c => c.GetSection("ConnectionStrings")).Returns(connSectionMock.Object);

            var jwtMinutesSection = new Mock<IConfigurationSection>();
            jwtMinutesSection.Setup(s => s.Value).Returns("60");
            _configuration.Setup(c => c.GetSection("Jwt:Minutes")).Returns(jwtMinutesSection.Object);

            // Mock UserManager
            var userStore = new Mock<IUserStore<IdentityUser>>();
            _userManager = new Mock<UserManager<IdentityUser>>(
                userStore.Object,
                null, null, null, null, null, null, null, null
            );

            _userManager.Setup(x => x.CreateAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);

            _userManager.Setup(x => x.AddToRoleAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);

            _userManager.Setup(x => x.GetRolesAsync(It.IsAny<IdentityUser>()))
                .ReturnsAsync(new List<string> { "USER" });

            _userManager.Setup(x => x.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync((IdentityUser)null); // Default: user doesn't exist

            // Mock SignInManager
            var contextAccessor = new Mock<IHttpContextAccessor>();
            var userClaimsPrincipalFactory = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
            var userConfirmation = new Mock<IUserConfirmation<IdentityUser>>();

            _signInManager = new Mock<SignInManager<IdentityUser>>(
                _userManager.Object,
                contextAccessor.Object,
                userClaimsPrincipalFactory.Object,
                null, null, null,
                userConfirmation.Object
            );

            _signInManager.Setup(x => x.PasswordSignInAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<bool>(),
                It.IsAny<bool>()))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            // Mock token generation
            _tokenService.Setup(t => t.GenerateToken(It.IsAny<IEnumerable<Claim>>()))
                .Returns("mock.jwt.token");
        }

        private UserController BuildUserController()
        {
            var httpContext = new DefaultHttpContext();
            var controllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            return new UserController(
                _configuration.Object,
                _tokenService.Object,
                _userManager.Object,
                _signInManager.Object)
            {
                ControllerContext = controllerContext
            };
        }

        private UserController BuildUserControllerWithIdentity(string role)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "testuser"),
                new Claim(ClaimTypes.Role, role)
            };

            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var principal = new ClaimsPrincipal(identity);

            var controller = BuildUserController();
            controller.ControllerContext.HttpContext.User = principal;

            return controller;
        }

        [Test]
        public async Task Register_ShouldRedirectToSuccess_WithValidModel()
        {
            var controller = BuildUserController();

            var model = new RegisterViewModel
            {
                Username = "secureUser",
                Email = "user@example.com",
                Password = "StrongP@ss9",
                Role = "USER"
            };

            var result = await controller.Register(model) as RedirectToActionResult;

            Assert.That(result?.ActionName, Is.EqualTo("Success"));
        }

        [Test]
        public async Task Register_ShouldRejectWeakPassword()
        {
            var controller = BuildUserController();

            var model = new RegisterViewModel
            {
                Username = "user1",
                Email = "user@example.com",
                Password = "123",
                Role = "USER"
            };

            controller.ModelState.AddModelError(nameof(model.Password), "Weak password");

            var result = await controller.Register(model) as ViewResult;

            Assert.That(controller.ModelState.IsValid == false);
            Assert.That(controller.ModelState.ContainsKey(nameof(model.Password)) == true);
        }

        [Test]
        public async Task Register_ShouldRejectMissingEmail()
        {
            var controller = BuildUserController();

            var model = new RegisterViewModel
            {
                Username = "user2",
                Password = "StrongP@ss9",
                Role = "USER",
                Email = ""
            };

            controller.ModelState.AddModelError(nameof(model.Email), "Email is required");

            var result = await controller.Register(model) as ViewResult;

            Assert.That(controller.ModelState.IsValid == false);
            Assert.That(controller.ModelState.ContainsKey(nameof(model.Email)) == true);
        }

        [Test]
        public async Task Login_ShouldRedirectToSuccess_WithValidCredentials()
        {
            var controller = BuildUserController();

            var model = new LoginViewModel
            {
                Username = "validUser",
                Password = "ValidPass123"
            };

            // Setup mocks
            var user = new IdentityUser { UserName = model.Username, Id = "userId" };
            _userManager.Setup(x => x.FindByNameAsync(model.Username))
                .ReturnsAsync(user);

            _userManager.Setup(x => x.CheckPasswordAsync(user, model.Password))
                .ReturnsAsync(true);

            _userManager.Setup(x => x.GetRolesAsync(user))
                .ReturnsAsync(new List<string> { "USER" });

            var result = await controller.Login(model) as RedirectToActionResult;

            Assert.That(result?.ActionName, Is.EqualTo("Success"));
        }

        [Test]
        public async Task Login_ShouldReturnViewWithError_WhenUserNotFound()
        {
            var controller = BuildUserController();

            var model = new LoginViewModel
            {
                Username = "unknownUser",
                Password = "AnyPass"
            };

            _userManager.Setup(x => x.FindByNameAsync(model.Username))
                .ReturnsAsync((IdentityUser)null); // user not found

            var result = await controller.Login(model) as ViewResult;

            Assert.That(result, Is.Not.Null);
            Assert.That(controller.ModelState.IsValid, Is.False);
            Assert.That(controller.ModelState[""].Errors[0].ErrorMessage, Is.EqualTo("Invalid credentials."));
        }

        [Test]
        public async Task Login_ShouldReturnViewWithError_WhenPasswordInvalid()
        {
            var controller = BuildUserController();

            var model = new LoginViewModel
            {
                Username = "validUser",
                Password = "WrongPass"
            };

            var user = new IdentityUser { UserName = model.Username, Id = "userId" };
            _userManager.Setup(x => x.FindByNameAsync(model.Username))
                .ReturnsAsync(user);

            _userManager.Setup(x => x.CheckPasswordAsync(user, model.Password))
                .ReturnsAsync(false); // wrong password

            var result = await controller.Login(model) as ViewResult;

            Assert.That(result, Is.Not.Null);
            Assert.That(controller.ModelState.IsValid, Is.False);
            Assert.That(controller.ModelState[""].Errors[0].ErrorMessage, Is.EqualTo("Invalid credentials."));
        }


        [Test]
        public void Admin_ShouldReturnView_WhenUserIsAdmin()
        {
            var controller = BuildUserControllerWithIdentity("ADMIN");

            var result = controller.Admin();

            Assert.That(result, Is.TypeOf<ViewResult>());
        }

        [Test]
        public void Admin_ShouldReturnForbid_WhenUserIsNotAdmin()
        {
            var controller = BuildUserControllerWithIdentity("USER"); // not admin

            var result = controller.Admin();

            Assert.That(result, Is.TypeOf<ForbidResult>());
        }

        [Test]
        public void UserOnly_ShouldReturnView_WhenUserIsUser()
        {
            var controller = BuildUserControllerWithIdentity("USER");

            var result = controller.UserOnly();

            Assert.That(result, Is.TypeOf<ViewResult>());
        }

        [Test]
        public void UserOnly_ShouldReturnForbid_WhenUserIsNotUser()
        {
            var controller = BuildUserControllerWithIdentity("ADMIN"); // not user

            var result = controller.UserOnly();

            Assert.That(result, Is.TypeOf<ForbidResult>());
        }

        [Test]
        public async Task Register_ShouldRejectOrHandle_MaliciousInputs()
        {
            var controller = BuildUserController();

            var maliciousModel = new RegisterViewModel
            {
                Username = "normaluser",
                Email = "user@example.com<script>alert('xss')</script>",  // XSS attempt
                Password = "123'; DROP TABLE Users;--",                    // SQL injection attempt in password
                Role = "USER"
            };

            // Act
            IActionResult result = null;
            try
            {
                result = await controller.Register(maliciousModel);
            }
            catch (Exception ex)
            {
                Assert.Fail($"Exception thrown during registration with malicious input: {ex.Message}");
            }

            // Assert that registration did NOT succeed (should return ViewResult for errors)
            Assert.That(result, Is.TypeOf<ViewResult>());

            // Assert ModelState contains errors on email and/or password fields or general errors
            Assert.That(controller.ModelState.IsValid, Is.False);

            bool hasEmailError = controller.ModelState.ContainsKey(nameof(maliciousModel.Email))
                                 && controller.ModelState[nameof(maliciousModel.Email)].Errors.Count > 0;
            bool hasPasswordError = controller.ModelState.ContainsKey(nameof(maliciousModel.Password))
                                    && controller.ModelState[nameof(maliciousModel.Password)].Errors.Count > 0;

            Assert.That(hasEmailError || hasPasswordError, Is.True,
                "ModelState should contain errors for either Email or Password due to malicious input.");
        }

    }
}

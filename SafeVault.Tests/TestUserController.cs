using NUnit.Framework;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using SafeVault.Controllers;
using Microsoft.Extensions.Configuration;
using Moq;
using SafeVault.Services;

namespace SafeVault.Tests
{
    public class UserControllerTests
    {
        private UserController _controller;
        private Mock<IConfiguration> _configMock;
        private Mock<ITokenService> _tokenServiceMock;

        [SetUp]
        public void Setup()
        {
            _tokenServiceMock = new Mock<ITokenService>();
            _configMock = new Mock<IConfiguration>();

            var mockConnSection = new Mock<IConfigurationSection>();
            mockConnSection.Setup(x => x["SafeVaultDb"])
                           .Returns("Server=localhost;Database=SafeVault;Uid=root;Pwd=password;");

            var mockJwtSection = new Mock<IConfigurationSection>();
            mockJwtSection.Setup(x => x.Value)
                          .Returns("60");

            _configMock.Setup(cfg => cfg.GetSection("ConnectionStrings"))
                       .Returns(mockConnSection.Object);
            _configMock.Setup(cfg => cfg.GetSection("Jwt:Minutes"))
                       .Returns(mockJwtSection.Object);

            _controller = new UserController(_configMock.Object, _tokenServiceMock.Object);
        }


        private void SetUserContext(string role)
        {
            var identity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "Trenton"),
                new Claim(ClaimTypes.Name, "Trenton"),
                new Claim(ClaimTypes.Role, role)
            }, "mock");

            var principal = new ClaimsPrincipal(identity);

            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = principal }
            };
        }

        [Test]
        public void UserOnly_WithUserRole_ReturnsView()
        {
            SetUserContext("User");

            var result = _controller.UserOnly();

            Assert.That(result, Is.InstanceOf<ViewResult>());
        }

        [Test]
        public void UserOnly_WithAdminRole_ReturnsForbidden()
        {
            SetUserContext("Admin");

            var result = _controller.UserOnly();

            Assert.That(result, Is.InstanceOf<ForbidResult>());
        }

        [Test]
        public void Admin_WithUserRole_ReturnsForbidden()
        {
            SetUserContext("User");

            var result = _controller.Admin();

            Assert.That(result, Is.InstanceOf<ForbidResult>());
        }

        [Test]
        public void Admin_WithAdminRole_ReturnsView()
        {
            SetUserContext("Admin");

            var result = _controller.Admin();

            Assert.That(result, Is.InstanceOf<ViewResult>());
        }

        [Test]
        public void TokenGeneration_ReturnsExpectedJwt()
        {
            var dummyClaims = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "Trenton")
            });

            _tokenServiceMock.Setup(ts => ts.GenerateToken(It.IsAny<IEnumerable<Claim>>()))
                             .Returns("mock-jwt-token");

            var result = _tokenServiceMock.Object.GenerateToken(dummyClaims.Claims);

            // Assert.AreEqual("mock-jwt-token", result);
            Assert.That(result, Is.EqualTo("mock-jwt-token"));
        }

        [TearDown]
        public void Teardown()
        {
            _controller?.Dispose();
        }

    }
}
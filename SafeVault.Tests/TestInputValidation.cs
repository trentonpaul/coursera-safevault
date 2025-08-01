using NUnit.Framework;
using SafeVault.Helpers;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        [Test]
        public void SanitizeUsername_ShouldRemoveSQLInjectionChars()
        {
            string input = "'; DROP TABLE Users; --";
            string sanitized = InputSanitizer.SanitizeUsername(input);

            Assert.That(sanitized, Is.EqualTo("DROPTABLEUsers"));
        }

        [Test]
        public void SanitizeUsername_ShouldBlockXSSScripts()
        {
            string input = "<script>alert('XSS')</script>";
            string sanitized = InputSanitizer.StripScriptTags(input);

            Assert.That(sanitized.Contains("<script>"), Is.False);
        }

        [Test]
        public void SanitizeEmail_ShouldRejectInvalidEmail()
        {
            Assert.Throws<FormatException>(() =>
                InputSanitizer.SanitizeEmail("not-an-email"));
        }

        [Test]
        public void SanitizeEmail_ShouldAllowValidEmail()
        {
            string input = "user@example.com";
            string sanitized = InputSanitizer.SanitizeEmail(input);

            Assert.That(sanitized, Is.EqualTo(input));
        }
    }
}

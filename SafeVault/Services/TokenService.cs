
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SafeVault.Services
{
    // Create and manage JWT tokens
    public class TokenService : ITokenService
    {
        private readonly string _jwtKey;
        private readonly string _jwtIssuer;
        private readonly string _jwtAudience;
        private readonly int _jwtMinutes;

        public TokenService(IConfiguration configuration)
        {
            _jwtKey = configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key is not configured.");
            _jwtIssuer = configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("JWT Issuer is not configured.");
            _jwtAudience = configuration["Jwt:Audience"] ?? throw new InvalidOperationException("JWT Audience is not configured.");
            _jwtMinutes = configuration.GetValue<int>("Jwt:Minutes") > 0 ? configuration.GetValue<int>("Jwt:Minutes") : 60;
        }

        // Additional methods for token creation and validation would go here
        public string GenerateToken(IEnumerable<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtIssuer,
                audience: _jwtAudience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(_jwtMinutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public interface ITokenService
    {
        string GenerateToken(IEnumerable<Claim> claims);
    }
}
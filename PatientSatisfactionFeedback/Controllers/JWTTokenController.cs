using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PatientSatisfactionFeedback.Context;
using PatientSatisfactionFeedback.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace PatientSatisfactionFeedback.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JWTTokenController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<JWTTokenController> _logger;

        public JWTTokenController(IConfiguration configuration, ApplicationDbContext context, ILogger<JWTTokenController> logger)
        {
            _configuration = configuration;
            _context = context;
            _logger = logger;
        }

        [HttpPost("generate-token")]
        public async Task<IActionResult> GenerateToken([FromBody] User user)
        {
            if (user == null || string.IsNullOrWhiteSpace(user.UserName) || string.IsNullOrWhiteSpace(user.Password))
                return BadRequest("Invalid user data.");

            var userData = await ValidateUserAsync(user.UserName, user.Password);
            if (userData == null)
                return Unauthorized("Invalid username or password.");

            var jwtSettings = _configuration.GetSection("Jwt").Get<Jwt>();
            var token = GenerateJwtToken(userData, jwtSettings);

            return Ok(new { Token = token });
        }

        private async Task<User> ValidateUserAsync(string username, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.Password)) // Hash password comparison
                return null;
            
            return user;
        }

        private string GenerateJwtToken(User user, Jwt jwtSettings)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, jwtSettings.Subject),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                new Claim("UserId", user.UserId.ToString()),
                new Claim("UserName", user.UserName),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: jwtSettings.Issuer,
                audience: jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

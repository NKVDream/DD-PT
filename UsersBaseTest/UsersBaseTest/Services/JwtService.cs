/*using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using UsersBaseTest.Models;

namespace UsersBaseTest.Services
{
    public class JwtService
    {
        private readonly string _secret;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly int _expiryMinutes;

        public JwtService(IConfiguration configuration)
        {
            _secret = configuration["JwtSettings:Secret"];
            _issuer = configuration["JwtSettings:Issuer"];
            _audience = configuration["JwtSettings:Audience"];
            _expiryMinutes = int.Parse(configuration["JwtSettings:ExpiryMinutes"]);
        }

        public string GenerateToken(users user, List<string> roles)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secret);

            var claims = new List<Claim>//claims
            {
                new Claim("id", user.id.ToString()),
                new Claim("username", user.username),
                new Claim("department", user.department ?? ""),
                new Claim("position", user.position ?? "")
            };

            foreach (var role in roles)//роли
            {
                claims.Add(new Claim("role", role));
            }

            var tokenDescriptor = new SecurityTokenDescriptor// токен
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_expiryMinutes),
                Issuer = _issuer,
                Audience = _audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
*/
// Services/JwtService.cs - обновленная версия
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using UsersBaseTest.Models;

namespace UsersBaseTest.Services
{
    public class JwtService
    {
        private readonly string _secret;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly int _expiryMinutes;

        public JwtService(IConfiguration configuration)
        {
            _secret = configuration["JwtSettings:Secret"];
            _issuer = configuration["JwtSettings:Issuer"];
            _audience = configuration["JwtSettings:Audience"];
            _expiryMinutes = int.Parse(configuration["JwtSettings:ExpiryMinutes"]);
        }

        public string GenerateToken(users user, List<string> roles, Dictionary<string, string>? additionalClaims = null)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secret);

            // 1. Базовые claims (утверждения)
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(ClaimTypes.NameIdentifier, user.id.ToString()),
                new Claim(ClaimTypes.Name, user.username),
                new Claim("userId", user.id.ToString()),
                new Claim("username", user.username),
                new Claim("department", user.department ?? ""),
                new Claim("position", user.position ?? ""),
                new Claim("createdAt", user.created_at.ToString("yyyy-MM-dd")),
                
                // Для политики ExperiencedEmployee (пример)
                // new Claim("hireDate", "2023-01-15") // Дату можно взять из БД
            };

            // 2. Добавляем роли в двух форматах (для совместимости)
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));  // Для [Authorize(Roles = "...")]
                claims.Add(new Claim("role", role));           // Для кастомных проверок
            }

            // 3. Дополнительные claims для политик
            if (additionalClaims != null)
            {
                foreach (var claim in additionalClaims)
                {
                    claims.Add(new Claim(claim.Key, claim.Value));
                }
            }

            // 4. Автоматически добавляем claims на основе данных пользователя
            if (user.department == "IT")
            {
                claims.Add(new Claim("itDepartment", "true"));
                claims.Add(new Claim("accessLevel", "technical"));
            }

            if (user.position?.Contains("Manager") == true ||
                user.position?.Contains("Administrator") == true ||
                user.position?.Contains("Director") == true)
            {
                claims.Add(new Claim("isManagement", "true"));
                claims.Add(new Claim("canApprove", "true"));
            }

            // 5. Создаем токен
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_expiryMinutes),
                Issuer = _issuer,
                Audience = _audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        // Метод для проверки и извлечения claims из токена
        public ClaimsPrincipal ValidateAndGetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_secret);

                var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _issuer,
                    ValidateAudience = true,
                    ValidAudience = _audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return principal;
            }
            catch
            {
                return null;
            }
        }

        // Метод для получения всех claims из токена
        public Dictionary<string, string> GetClaimsFromToken(string token)
        {
            var claims = new Dictionary<string, string>();

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            foreach (var claim in jwtToken.Claims)
            {
                claims[claim.Type] = claim.Value;
            }

            return claims;
        }
    }
}

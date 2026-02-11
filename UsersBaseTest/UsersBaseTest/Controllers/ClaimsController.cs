using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using UsersBaseTest.Models;
using UsersBaseTest.Services;

namespace UsersBaseTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ClaimsController : ControllerBase
    {
        private readonly JwtService _jwtService;

        public ClaimsController(JwtService jwtService)
        {
            _jwtService = jwtService;
        }

        // 1. Просмотр всех claims текущего пользователя
        [HttpGet("my-claims")]
        [Authorize]
        public IActionResult GetMyClaims()
        {
            var claims = User.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value,
                ValueType = c.ValueType
            }).ToList();

            return Ok(new
            {
                Username = User.Identity?.Name,
                ClaimsCount = claims.Count,
                Claims = claims
            });
        }

        // 2. Проверка наличия конкретного claim
        [HttpGet("check-claim/{claimType}/{claimValue}")]
        [Authorize]
        public IActionResult CheckClaim(string claimType, string claimValue)
        {
            var hasClaim = User.HasClaim(claimType, claimValue);

            return Ok(new
            {
                HasClaim = hasClaim,
                ClaimType = claimType,
                ClaimValue = claimValue,
                Message = hasClaim ? "Claim найден" : "Claim не найден"
            });
        }

        // 3. Динамическая проверка claims
        [HttpPost("custom-access")]
        [Authorize]
        public IActionResult CustomAccess([FromBody] AccessRequest request)
        {
            // Проверяем все required claims
            foreach (var requiredClaim in request.RequiredClaims)
            {
                if (!User.HasClaim(requiredClaim.Type, requiredClaim.Value))
                {
                    return Forbid($"Требуется claim: {requiredClaim.Type}={requiredClaim.Value}");
                }
            }

            return Ok(new
            {
                Message = "Доступ разрешен на основе claims",
                UserClaims = User.Claims
                    .Where(c => request.RequiredClaims.Any(rc => rc.Type == c.Type))
                    .Select(c => new { c.Type, c.Value })
            });
        }

        // 4. Генерация токена с кастомными claims
        [HttpPost("generate-with-claims")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GenerateTokenWithClaims([FromBody] TokenGenerationRequest request)
        {
            // Здесь логика получения пользователя и ролей из БД
            // Для примера используем фиктивные данные

            var additionalClaims = new Dictionary<string, string>
            {
                { "project", request.Project },
                { "accessLevel", request.AccessLevel },
                { "expiresAt", DateTime.UtcNow.AddHours(request.HoursValid).ToString("o") }
            };

            // Добавляем кастомные claims из запроса
            foreach (var claim in request.CustomClaims)
            {
                additionalClaims[claim.Key] = claim.Value;
            }

            // Пример пользователя
            var user = new users
            {
                id = 1,
                username = "test",
                department = "IT",
                position = "Developer"
            };

            var roles = new List<string> { "Employee" };
            var token = _jwtService.GenerateToken(user, roles, additionalClaims);

            return Ok(new
            {
                Token = token,
                Claims = additionalClaims,
                ExpiresIn = $"{request.HoursValid} часов"
            });
        }

        // 5. Авторизация на основе нескольких claims (ручная проверка)
        [HttpGet("multi-claim-access")]
        public IActionResult MultiClaimAccess()
        {
            // Ручная проверка без [Authorize]
            if (!User.Identity?.IsAuthenticated ?? true)
                return Unauthorized("Требуется аутентификация");

            // Проверяем комбинацию claims
            var isIT = User.HasClaim("department", "IT");
            var isManager = User.HasClaim("position", "Manager") ||
                           User.HasClaim("position", "Administrator");
            var hasTechnicalAccess = User.HasClaim("accessLevel", "technical");

            if (isIT && (isManager || hasTechnicalAccess))
            {
                return Ok(new
                {
                    Message = "Доступ к техническому порталу разрешен",
                    UserInfo = new
                    {
                        Department = User.FindFirst("department")?.Value,
                        Position = User.FindFirst("position")?.Value,
                        IsManagement = User.HasClaim("isManagement", "true")
                    }
                });
            }

            return Forbid("Недостаточно прав для доступа к техническому порталу");
        }
    }

    // Модели для запросов
    public class AccessRequest
    {
        public List<ClaimRequirement> RequiredClaims { get; set; } = new();
    }

    public class ClaimRequirement
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }

    public class TokenGenerationRequest
    {
        public string Project { get; set; }
        public string AccessLevel { get; set; }
        public int HoursValid { get; set; } = 1;
        public Dictionary<string, string> CustomClaims { get; set; } = new();
    }
}
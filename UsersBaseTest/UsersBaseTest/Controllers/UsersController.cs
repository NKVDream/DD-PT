/*
using UsersBaseTest.Data;
using UsersBaseTest.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace UsersBaseTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _context;
    public UsersController(AppDbContext context)
    {
        _context = context;
    }
    [HttpGet]
    public async Task<ActionResult<IEnumerable<users>>> GetUsers()
    {
        return await _context.users.ToListAsync();
    }
    [HttpGet("{id}")]
    public async Task<ActionResult<users>> GetUsers(int id)
    {
        var user = await _context.users.FindAsync(id);

        if (user == null)
        {
            return NotFound();
        }
        return user;
    }
    [HttpPost]
    public async Task<ActionResult<users>> PostUsers(users user)
    {
        _context.users.Add(user);
        await _context.SaveChangesAsync();

        return CreatedAtAction("GetUsers", new { id = user.Id }, user);
    }
    [HttpPut("{id}")]
    public async Task<IActionResult> PutUsers(int id, users user)
    {
        if (id != user.Id)
        {
            return BadRequest();
        }
        _context.Entry(user).State = EntityState.Modified;

        try
        {
            await _context.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException)
        {
            if (!UserExists(id))
            {
                return NotFound();
            }
            else
            {
                throw;
            }
        }
        return NoContent();
    }
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var user = await _context.users.FindAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        _context.users.Remove(user);
        await _context.SaveChangesAsync();

        return NoContent();
    }

    private bool UserExists(int id)
    {
        return _context.users.Any(e => e.Id == id);
    }
}

using UsersBaseTest.Data;
using UsersBaseTest.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace UsersBaseTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _context;

    public UsersController(AppDbContext context)
    {
        _context = context;
    }

    // Простой POST для регистрации
    [HttpPost("register BCrypt")]
    public async Task<IActionResult> Register(string username, string password)
    {
        
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);//Хешируем пароль с автоматической генерацией соли

        
        var user = new users
        {
            username = username,
            password_hash = passwordHash, //Сохраняем хеш
            created_at = DateTime.UtcNow
        };

        
        _context.users.Add(user);//Сохраняем в БД
        await _context.SaveChangesAsync();

        return Ok($"Пользователь создан. Хеш пароля: {passwordHash}");
    }

    
    [HttpPost("login BCrypt")]
    public async Task<IActionResult> Login(string username, string password)
    {
        // 1. Находим пользователя
        var user = await _context.users
            .FirstOrDefaultAsync(u => u.username == username);

        if (user == null)
            return BadRequest("Пользователь не найден");

        // 2. Проверяем пароль (BCrypt сам достает соль из хеша!)
        bool isPasswordValid = BCrypt.Net.BCrypt.Verify(password, user.password_hash);

        if (isPasswordValid)
            return Ok("Пароль верный");
        else
            return BadRequest("Пароль неверный");
    }

    // Простой GET чтобы посмотреть пользователей
    [HttpGet]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _context.users.ToListAsync();
        return Ok(users);
    }
}

using UsersBaseTest.Data;
using UsersBaseTest.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace UsersBaseTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _context;

    public UsersController(AppDbContext context)
    {
        _context = context;
    }
    // В UsersController.cs добавьте этот метод:
    [HttpPost("setup-test-data")]
    [AllowAnonymous] // Разрешаем без авторизации для удобства
    public async Task<IActionResult> SetupTestData()
    {
        try
        {
            // 1. Проверяем и создаем таблицы если их нет
            await _context.Database.EnsureCreatedAsync();

            // 2. Очищаем существующие данные (если есть)
            if (await _context.users.AnyAsync())
            {
                _context.user_roles.RemoveRange(_context.user_roles);
                _context.users.RemoveRange(_context.users);
                _context.roles.RemoveRange(_context.roles);
                await _context.SaveChangesAsync();
            }

            // 3. Создаем роли
            var roles = new List<roles>
        {
            new roles { name = "Admin", description = "Администратор системы" },
            new roles { name = "Manager", description = "Менеджер отдела" },
            new roles { name = "Developer", description = "Разработчик" },
            new roles { name = "Analyst", description = "Аналитик" },
            new roles { name = "User", description = "Обычный пользователь" }
        };

            await _context.roles.AddRangeAsync(roles);
            await _context.SaveChangesAsync();

            // 4. Создаем пользователей
            var users = new List<users>
        {
            new users
            {
                username = "admin",
                password_hash = BCrypt.Net.BCrypt.HashPassword("admin123"),
                department = "IT",
                position = "Системный администратор",
                created_at = DateTime.UtcNow
            },
            new users
            {
                username = "manager",
                password_hash = BCrypt.Net.BCrypt.HashPassword("manager123"),
                department = "Продажи",
                position = "Менеджер по продажам",
                created_at = DateTime.UtcNow
            },
            new users
            {
                username = "developer",
                password_hash = BCrypt.Net.BCrypt.HashPassword("dev123"),
                department = "Разработка",
                position = "Senior Developer",
                created_at = DateTime.UtcNow
            },
            new users
            {
                username = "analyst",
                password_hash = BCrypt.Net.BCrypt.HashPassword("analyst123"),
                department = "Маркетинг",
                position = "Бизнес-аналитик",
                created_at = DateTime.UtcNow
            },
            new users
            {
                username = "user1",
                password_hash = BCrypt.Net.BCrypt.HashPassword("user123"),
                department = "Поддержка",
                position = "Специалист поддержки",
                created_at = DateTime.UtcNow
            }
        };

            await _context.users.AddRangeAsync(users);
            await _context.SaveChangesAsync();

            // 5. Назначаем роли
            var userRoles = new List<user_roles>();

            var adminUser = users.First(u => u.username == "admin");
            var adminRole = roles.First(r => r.name == "Admin");
            userRoles.Add(new user_roles { user_id = adminUser.id, role_id = adminRole.id });

            var managerUser = users.First(u => u.username == "manager");
            var managerRole = roles.First(r => r.name == "Manager");
            userRoles.Add(new user_roles { user_id = managerUser.id, role_id = managerRole.id });

            var developerUser = users.First(u => u.username == "developer");
            var developerRole = roles.First(r => r.name == "Developer");
            userRoles.Add(new user_roles { user_id = developerUser.id, role_id = developerRole.id });

            var analystUser = users.First(u => u.username == "analyst");
            var analystRole = roles.First(r => r.name == "Analyst");
            userRoles.Add(new user_roles { user_id = analystUser.id, role_id = analystRole.id });

            var regularUser = users.First(u => u.username == "user1");
            var userRole = roles.First(r => r.name == "User");
            userRoles.Add(new user_roles { user_id = regularUser.id, role_id = userRole.id });

            await _context.user_roles.AddRangeAsync(userRoles);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                success = true,
                message = "Тестовые данные созданы успешно!",
                users_created = users.Count,
                roles_created = roles.Count
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new
            {
                success = false,
                message = $"Ошибка: {ex.Message}",
                details = ex.InnerException?.Message
            });
        }
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(string username, string password,
        string? department = null, string? position = null)
    {
        // Проверяем уникальность username
        if (await _context.users.AnyAsync(u => u.username == username))
            return BadRequest("Username already exists");

        // Хэшируем пароль с BCrypt (соль генерируется автоматически внутри)
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

        var user = new users
        {
            username = username,
            password_hash = passwordHash, // Здесь уже есть и хэш и соль
            department = department,
            position = position,
            created_at = DateTime.UtcNow
        };

        _context.users.Add(user);
        await _context.SaveChangesAsync();

        return Ok($"User {username} created");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(string username, string password)
    {
        var user = await _context.users
            .FirstOrDefaultAsync(u => u.username == username);

        if (user == null)
            return Unauthorized("User not found");

        // BCrypt сам достает соль из password_hash и проверяет
        bool isPasswordValid = BCrypt.Net.BCrypt.Verify(password, user.password_hash);

        if (!isPasswordValid)
            return Unauthorized("Invalid password");

        return Ok($"Welcome {username}!");
    }

    // Метод для миграции старых пользователей
    [HttpPost("migrate-old-users")]
    public async Task<IActionResult> MigrateOldUsers()
    {
        // Находим пользователей с NULL в department/position
        var oldUsers = await _context.users
            .Where(u => u.department == null || u.position == null)
            .ToListAsync();

        foreach (var user in oldUsers)
        {
            // Устанавливаем дефолтные значения
            user.department = user.department ?? "General";
            user.position = user.position ?? "Employee";
        }

        await _context.SaveChangesAsync();
        return Ok($"Migrated {oldUsers.Count} users");
    }
}
*/
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using UsersBaseTest.Data;
using UsersBaseTest.Models;
using UsersBaseTest.Services;

namespace UsersBaseTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly JwtService _jwtService;

    public UsersController(AppDbContext context, JwtService jwtService)
    {
        _context = context;
        _jwtService = jwtService;
    }

    // 1. РЕГИСТРАЦИЯ
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register(string username, string password,
        string? department = null, string? position = null)
    {
        // Проверяем, существует ли пользователь
        if (await _context.users.AnyAsync(u => u.username == username))
            return BadRequest("Пользователь уже существует");

        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

        var user = new users
        {
            username = username,
            password_hash = passwordHash,
            department = department,
            position = position,
            created_at = DateTime.UtcNow
        };

        _context.users.Add(user);
        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Пользователь создан",
            username = user.username,
            id = user.id
        });
    }

    // 2. ВХОД С ПОЛУЧЕНИЕМ JWT ТОКЕНА
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string username, string password)
    {
        // Находим пользователя
        var user = await _context.users
            .FirstOrDefaultAsync(u => u.username == username);

        if (user == null)
            return Unauthorized("Пользователь не найден");

        // Проверяем пароль
        bool isPasswordValid = BCrypt.Net.BCrypt.Verify(password, user.password_hash);

        if (!isPasswordValid)
            return Unauthorized("Неверный пароль");

        // Получаем роли пользователя
        var roles = await _context.user_roles
            .Where(ur => ur.user_id == user.id)
            .Join(_context.roles,
                ur => ur.role_id,
                r => r.id,
                (ur, r) => r.name)
            .ToListAsync();

        // Генерируем JWT токен
        var token = _jwtService.GenerateToken(user, roles);

        return Ok(new
        {
            token = token,
            user = new
            {
                id = user.id,
                username = user.username,
                department = user.department,
                position = user.position,
                roles = roles
            }
        });
    }

    // 3. ПРОВЕРКА ТОКЕНА (получить информацию о себе)
    [HttpGet("me")]
    [Authorize] // Требует валидный JWT токен
    public IActionResult GetMyInfo()
    {
        // Информация из токена (автоматически заполняется из claims)
        var userId = User.FindFirst("id")?.Value;
        var username = User.FindFirst("username")?.Value;
        var department = User.FindFirst("department")?.Value;
        var position = User.FindFirst("position")?.Value;

        // Получаем все роли из claims
        var roles = User.Claims
            .Where(c => c.Type == "role")
            .Select(c => c.Value)
            .ToList();

        return Ok(new
        {
            id = userId,
            username = username,
            department = department,
            position = position,
            roles = roles,
            message = "Это ваши данные из JWT токена"
        });
    }

    // 4. ЗАЩИЩЕННЫЙ МЕТОД (только для админов)
    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")] // Только пользователи с ролью Admin
    public IActionResult AdminOnly()
    {
        return Ok(new
        {
            message = "Это доступно только администраторам!",
            user = User.FindFirst("username")?.Value,
            time = DateTime.Now
        });
    }

    // 5. ЗАЩИЩЕННЫЙ МЕТОД (для нескольких ролей)
    [HttpGet("managers-and-admins")]
    [Authorize(Roles = "Admin,Manager")] // Админы и менеджеры
    public IActionResult ManagersAndAdmins()
    {
        return Ok(new
        {
            message = "Это для менеджеров и администраторов",
            your_roles = User.Claims
                .Where(c => c.Type == "role")
                .Select(c => c.Value)
                .ToList()
        });
    }

    // 6. ПУБЛИЧНЫЙ МЕТОД (без авторизации)
    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult PublicInfo()
    {
        return Ok(new
        {
            message = "Это публичная информация, доступна всем",
            time = DateTime.Now
        });
    }

    // 7. ПРОВЕРКА ТОКЕНА (просто валидация)
    [HttpPost("validate-token")]
    [AllowAnonymous]
    public IActionResult ValidateToken([FromBody] string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(token);

            return Ok(new
            {
                valid = true,
                expires = jsonToken.ValidTo,
                username = jsonToken.Claims.FirstOrDefault(c => c.Type == "username")?.Value,
                roles = jsonToken.Claims.Where(c => c.Type == "role").Select(c => c.Value)
            });
        }
        catch
        {
            return BadRequest(new { valid = false });
        }
    }
    [HttpGet("admin-dashboard")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminDashboard()
    {
        return Ok(new
        {
            Message = "Панель администратора",
            Description = "Полный доступ ко всем функциям системы",
            Timestamp = DateTime.Now,
            User = User.Identity?.Name
        });
    }

    [HttpGet("management-reports")]
    [Authorize(Roles = "Admin,Manager")]
    public IActionResult ManagementReports()
    {
        return Ok(new
        {
            Message = "Отчеты для руководства",
            Data = new
            {
                Sales = "$1,234,567",
                UsersCount = 150,
                ActiveProjects = 23
            },
            AccessLevel = "Management"
        });
    }

    // 3. Для сотрудников и выше
    [HttpGet("employee-tasks")]
    [Authorize(Roles = "Admin,Manager,Employee")]
    public IActionResult EmployeeTasks()
    {
        return Ok(new
        {
            Message = "Задачи сотрудников",
            Tasks = new[]
            {
            new { Id = 1, Title = "Разработка фичи", Status = "В процессе" },
            new { Id = 2, Title = "Code review", Status = "Ожидает" }
        }
        });
    }

    // 4. Для просмотра (самый низкий уровень)
    [HttpGet("public-info")]
    [Authorize(Roles = "Admin,Manager,Employee,Viewer")]
    public IActionResult PublicInfoo()
    {
        return Ok(new
        {
            Message = "Общая информация компании",
            Company = "Our Company Inc.",
            Established = 2025,
            Departments = new[] { "IT", "Sales", "Marketing" }
        });
    }

    // 5. Разные роли для разных методов одного ресурса
    public class DocumentsController : ControllerBase
    {
        [HttpGet("documents")]
        [Authorize(Roles = "Admin,Manager,Employee,Viewer")]
        public IActionResult GetDocuments()
        {
            return Ok(new[] { "Document1.pdf", "Document2.docx" });
        }

        [HttpPost("documents")]
        [Authorize(Roles = "Admin,Manager")]
        public IActionResult UploadDocument()
        {
            return Ok("Документ загружен");
        }

        [HttpDelete("documents/{id}")]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteDocument(int id)
        {
            return Ok($"Документ {id} удален");
        }
    }
    [HttpGet("it-resources")]
    [Authorize(Policy = "ITDepartment")]
    public IActionResult GetITResources()
    {
        return Ok(new
        {
            Message = "Ресурсы IT отдела",
            Resources = new[] { "Сервера", "Лицензии ПО", "Сетевое оборудование" }
        });
    }

    // 2. Для руководящих должностей
    [HttpGet("salary-reports")]
    [Authorize(Policy = "SeniorPosition")]
    public IActionResult GetSalaryReports()
    {
        return Ok(new
        {
            Message = "Отчеты по зарплатам",
            Note = "Доступно только руководству",
            Data = "Конфиденциальная информация"
        });
    }

    // 3. Для опытных сотрудников
    [HttpGet("mentor-program")]
    [Authorize(Policy = "ExperiencedEmployee")]
    public IActionResult GetMentorProgram()
    {
        return Ok(new
        {
            Message = "Программа наставничества",
            Description = "Только для сотрудников с опытом более 1 года"
        });
    }

    // 4. Комбинированная политика
    [HttpGet("it-management")]
    [Authorize(Policy = "ITManager")]
    public IActionResult GetITManagement()
    {
        return Ok(new
        {
            Message = "Управление IT отделом",
            Responsibilities = new[]
            {
            "Бюджет отдела",
            "Закупка оборудования",
            "Управление персоналом"
        }
        });
    }

    // 5. Несколько политик одновременно
    [HttpGet("business-sensitive")]
    [Authorize(Policy = "SeniorPosition")]
    [Authorize(Policy = "BusinessHours")]
    public IActionResult GetBusinessSensitiveData()
    {
        return Ok(new
        {
            Message = "Чувствительные бизнес-данные",
            AccessCondition = "Только руководство в рабочее время",
            Data = "Финансовые показатели Q4"
        });
    }
}
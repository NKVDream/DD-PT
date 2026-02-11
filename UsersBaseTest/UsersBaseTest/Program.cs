/*
using Microsoft.EntityFrameworkCore;
using UsersBaseTest.Data;

var builder = WebApplication.CreateBuilder(args);
//using Microsoft.EntityFrameworkCore;
//using UsersBaseTest.Data;

//var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddControllers();

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();

using UsersBaseTest.Data;
using UsersBaseTest.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Добавляем DbContext
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Добавляем JWT сервис
builder.Services.AddScoped<JwtService>();

// НАСТРОЙКА JWT АУТЕНТИФИКАЦИИ
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secret = jwtSettings["Secret"] ?? "fallback-secret-key-minimum-32-chars";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
        ClockSkew = TimeSpan.Zero // Без задержки
    };

    // Для тестов в Swagger можно отключить некоторые проверки
    options.RequireHttpsMetadata = false; // Только для разработки!
});

// Настраиваем авторизацию по ролям
builder.Services.AddAuthorization(options =>
{
    // Можно создать кастомные политики если нужно
    options.AddPolicy("ITDepartment", policy =>
        policy.RequireClaim("department", "IT"));
});

builder.Services.AddControllers();

var app = builder.Build();

// ВАЖНО: Сначала аутентификация, потом авторизация
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

using UsersBaseTest.Data;
using UsersBaseTest.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Добавляем сервисы
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// База данных
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Наши сервисы
builder.Services.AddScoped<JwtService>();

// ВАЖНО: Добавляем аутентификацию
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false, // Упрощаем для тестов
            ValidateAudience = false, // Упрощаем для тестов
            ValidateLifetime = true, // Проверяем срок действия
            ValidateIssuerSigningKey = true, // Проверяем подпись
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Secret"]))
        };
    });

var app = builder.Build();

// Используем аутентификацию и авторизацию
app.UseAuthentication(); // ВАЖНО: ДО UseAuthorization!
app.UseAuthorization();
// В Program.cs после AddAuthentication()
builder.Services.AddAuthorization(options =>
{
    // 1. Политика для IT отдела (по claim'у department)
    options.AddPolicy("ITDepartment", policy =>
        policy.RequireClaim("department", "IT"));

    // 2. Политика для руководящих должностей
    options.AddPolicy("SeniorPosition", policy =>
        policy.RequireClaim("position", "Administrator", "Manager", "Director"));

    // 3. Политика по стажу (минимальный срок работы)
    options.AddPolicy("ExperiencedEmployee", policy =>
        policy.RequireAssertion(context =>
        {
            var hireDateClaim = context.User.FindFirst("hireDate");
            if (hireDateClaim == null) return false;

            if (DateTime.TryParse(hireDateClaim.Value, out var hireDate))
            {
                var experience = DateTime.Now - hireDate;
                return experience.TotalDays > 365; // Больше года
            }
            return false;
        }));

    // 4. Комбинированная политика (IT менеджер)
    options.AddPolicy("ITManager", policy =>
    {
        policy.RequireRole("Manager");
        policy.RequireClaim("department", "IT");
    });

    // 5. Политика для работы в рабочее время
    options.AddPolicy("BusinessHours", policy =>
        policy.RequireAssertion(context =>
        {
            var now = DateTime.Now;
            return now.Hour >= 9 && now.Hour < 18 && now.DayOfWeek != DayOfWeek.Saturday && now.DayOfWeek != DayOfWeek.Sunday;
        }));

    // 6. Политика по нескольким ролям (альтернатива Roles = "A,B")
    options.AddPolicy("AdminOrManager", policy =>
        policy.RequireAssertion(context =>
            context.User.IsInRole("Admin") || context.User.IsInRole("Manager")));
});
app.UseSwagger();
app.UseSwaggerUI();

app.MapControllers();

app.Run();
*/
using UsersBaseTest.Data;
using UsersBaseTest.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. ДОБАВЛЯЕМ ВСЕ СЕРВИСЫ ДО builder.Build()
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// База данных
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Наши сервисы
builder.Services.AddScoped<JwtService>();

// Аутентификация JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Secret"]))
        };
    });

// АВТОРИЗАЦИЯ И ПОЛИТИКИ (ВАЖНО: ДО builder.Build()!)
builder.Services.AddAuthorization(options =>
{
    // 1. Политика для IT отдела
    options.AddPolicy("ITDepartment", policy =>
        policy.RequireClaim("department", "IT"));

    // 2. Политика для руководящих должностей
    options.AddPolicy("SeniorPosition", policy =>
        policy.RequireClaim("position", "Administrator", "Manager", "Director"));

    // 3. Упрощенная политика AdminOrManager
    options.AddPolicy("AdminOrManager", policy =>
        policy.RequireRole("Admin", "Manager"));

    // 4. Комбинированная политика (IT менеджер)
    options.AddPolicy("ITManager", policy =>
    {
        policy.RequireRole("Manager");
        policy.RequireClaim("department", "IT");
    });
});

// 2. ТЕПЕРЬ СОЗДАЕМ app
var app = builder.Build();

// 3. НАСТРАИВАЕМ PIPELINE
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// ВАЖНО: Сначала аутентификация, потом авторизация
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
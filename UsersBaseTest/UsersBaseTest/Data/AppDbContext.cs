// Data/AppDbContext.cs (упрощенная версия)
using Microsoft.EntityFrameworkCore;
using UsersBaseTest.Models;

namespace UsersBaseTest.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<users> users { get; set; }
        public DbSet<roles> roles { get; set; }
        public DbSet<user_roles> user_roles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Просто указываем первичные ключи, остальное EF поймет сам
            modelBuilder.Entity<users>().HasKey(u => u.id);
            modelBuilder.Entity<roles>().HasKey(r => r.id);
            modelBuilder.Entity<user_roles>().HasKey(ur => new { ur.user_id, ur.role_id });
        }
    }
}
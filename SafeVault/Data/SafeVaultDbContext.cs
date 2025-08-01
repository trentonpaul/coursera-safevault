// using Microsoft.EntityFrameworkCore;
// using SafeVault.Models;

// namespace SafeVault.Data
// {
//     public class SafeVaultDbContext : DbContext
//     {
//         public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options)
//             : base(options)
//         {
//         }

//         public DbSet<User> Users { get; set; }

//         protected override void OnModelCreating(ModelBuilder modelBuilder)
//         {
//             modelBuilder.Entity<User>().ToTable("Users");
            
//             // Optional: enforce additional constraints at the DB level
//             modelBuilder.Entity<User>()
//                 .Property(u => u.Username)
//                 .IsRequired()
//                 .HasMaxLength(100);

//             modelBuilder.Entity<User>()
//                 .Property(u => u.Email)
//                 .IsRequired()
//                 .HasMaxLength(100);
//         }
//     }
// }
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Auth.Models;





namespace Auth.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext (DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Global Query Filter
            // This ensures EF Core automatically adds WHERE IsDeleted = 0 to ALL ApplicationUser queries.
            builder.Entity<ApplicationUser>().HasQueryFilter(u => !u.IsDeleted);
        }
    }
}

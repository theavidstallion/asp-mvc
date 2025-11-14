using Auth.Models;
using Microsoft.AspNetCore.Identity;

namespace Auth.Data
{
    public static class DataSeeder
    {
        private const string AdminEmail = "admin@devfarooq.me";
        private const string AdminPassword = "Admin@12345";
        private const string AdminRole = "Admin";
        private const string UserRole = "User";
        private const string AdminPhoneNumber = "+1234567890";
        private const string AuthMethod = "System";


        public static async Task InitializeAsync (
            UserManager<ApplicationUser> userManager,
            RoleManager< IdentityRole > roleManager)
        {
            if (await roleManager.FindByNameAsync(AdminRole) == null) {
                await roleManager.CreateAsync(new IdentityRole(AdminRole));
            }
            if (await roleManager.FindByNameAsync(UserRole) == null) {
                await roleManager.CreateAsync(new IdentityRole(UserRole));
            }
            if (await userManager.FindByEmailAsync(AdminEmail) == null)
            {
                var AdminUser = new ApplicationUser
                {
                    UserName = AdminEmail,
                    Email = AdminEmail,
                    PhoneNumber = AdminPhoneNumber,
                    FirstName = "Administrator",
                    LastName = "N/A",
                    EmailConfirmed = true,
                    AuthMethod = AuthMethod,
                    City = "N/A"
                };

                var result = await userManager.CreateAsync(AdminUser, AdminPassword);

                if (result.Succeeded) 
                { 
                    await userManager.AddToRoleAsync(AdminUser, AdminRole);
                }
            }

        }
        
    }
}

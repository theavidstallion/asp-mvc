using Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;


namespace Auth.Controllers
{
    public class AdminController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AdminController> _logger;
        private readonly IConfiguration _configuration;

        public AdminController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, ILogger<AdminController> logger, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _logger = logger;
            _configuration = configuration;
        }


        // --------------
        // Admin Actions
        // --------------


        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UserManagement()
        {
            var users = await _userManager.Users
                .Where(u => u.Email != "admin@devfarooq.me")
                .ToListAsync();
            return View(users);
        }


        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AdminDeleteUser(string targetUserId)
        {
            var user = await _userManager.FindByIdAsync(targetUserId);
            if (user == null) { return NotFound(); }

            if (user.Email == "admin@devfarooq.me")
            {
                TempData["ErrorMessage"] = "Cannot delete the primary admin account.";
                return RedirectToAction("UserManagement");
            }

            // DateTime Conversion
            TimeSpan offset = TimeSpan.FromHours(5);
            DateTimeOffset userDateTimeOffset = DateTimeOffset.UtcNow.ToOffset(offset);

            var adminEmail = User.Identity.Name;

            // Soft delete by setting IsDeleted flag
            user.IsDeleted = true;
            user.DeletedBy = adminEmail;
            user.DeletedAt = userDateTimeOffset;

            var result = await _userManager.UpdateAsync(user);


            if (result.Succeeded)
            {
                if (_userManager.GetUserId(User) == targetUserId)
                {
                    _logger.LogWarning("Admin {AdminEmail} soft-deleted their own account.", adminEmail);
                    // If admin deleted their own account, sign them out
                    TempData["SuccessMessage"] = "Deleted your account successfully.";
                    await _signInManager.SignOutAsync();
                    return RedirectToAction("Index", "Home");
                }

                _logger.LogWarning("Admin {AdminEmail} soft-deleted user account {UserEmail}.", adminEmail, user.Email);
                TempData["SuccessMessage"] = "User deleted successfully.";
            }
            else
            {
                TempData["ErrorMessage"] = "Error deleting user.";
            }
            return RedirectToAction("UserManagement");
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AdminChangeRole(string targetUserId)
        {
            var user = await _userManager.FindByIdAsync(targetUserId);
            if (user == null) { return NotFound(); }

            var allRoles = await _roleManager.Roles.Select(r => r.Name).ToListAsync();
            var userRoles = await _userManager.GetRolesAsync(user);

            ViewData["UserId"] = targetUserId;
            ViewData["UserName"] = user.Email;
            ViewData["AllRoles"] = allRoles;
            ViewData["UserRoles"] = userRoles;
            ViewData["CurrentRole"] = userRoles.FirstOrDefault() ?? "No Role Assigned";


            return View();

        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AdminChangeRole(string targetUserId, string newRole)
        {
            var adminUser = await _userManager.GetUserAsync(User);
            var user = await _userManager.FindByIdAsync(targetUserId);
            if (user == null) { return NotFound(); }

            var currentRoles = await _userManager.GetRolesAsync(user);
            var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);

            if (!removeResult.Succeeded)
            {
                TempData["ErrorMessage"] = "Error changing user role.";
                return RedirectToAction("AdminChangeRole", new { targetUserId = targetUserId });
            }

            // DateTime Conversion

            TimeSpan offset = TimeSpan.FromHours(5);
            DateTimeOffset userDateTimeOffset = DateTimeOffset.UtcNow.ToOffset(offset);


            // Log role change details
            user.RoleChangedBy = adminUser.FirstName;
            user.RoleChangedDate = userDateTimeOffset;
            user.RoleChangedFrom = currentRoles.FirstOrDefault() ?? "No Role Assigned";
            var addResult = await _userManager.AddToRoleAsync(user, newRole);


            if (addResult.Succeeded)
            {
                TempData["SuccessMessage"] = "User role updated successfully.";
                _logger.LogInformation("Admin {AdminEmail} changed role of user {UserEmail} from {OldRole} to {NewRole}.", adminUser.Email, user.Email, user.RoleChangedFrom, newRole);
                if (adminUser.Id == user.Id)
                {
                    // If admin changed their own role, sign them out to refresh permissions
                    await _signInManager.SignOutAsync();
                    _logger.LogInformation("Admin {AdminEmail} changed their own role and has been signed out to refresh permissions.", adminUser.Email);
                    return RedirectToAction("Login", "Auth");
                }
            }
            else
            {
                TempData["ErrorMessage"] = "Error changing user role: " + addResult.Errors.FirstOrDefault()?.Description;
                _logger.LogWarning("Admin {AdminEmail} Failed to change role for user {UserEmail}. Errors: {Errors}", adminUser.Email, user.Email, string.Join(", ", addResult.Errors));
                return RedirectToAction("AdminChangeRole", new { targetUserId = targetUserId });
            }

            return RedirectToAction("UserManagement");
        }


        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> Logs()
        {
            // You will need to inject IConfiguration to get the connection string
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            var logs = new List<AppLogs>();

            // Use raw ADO.NET or Dapper (or EF Core's FromSqlRaw) to query the unmanaged table
            using (var connection = new Microsoft.Data.SqlClient.SqlConnection(connectionString))
            {
                // Example using Dapper (or simplified ADO.NET) syntax:
                await connection.OpenAsync();
                var command = new Microsoft.Data.SqlClient.SqlCommand("SELECT Id, TimeStamp, Level, Message, Exception FROM AppLogs ORDER BY TimeStamp DESC", connection);

                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        logs.Add(new AppLogs
                        {
                            Id = reader.GetInt32(0),
                            TimeStamp = reader.GetDateTime(1),
                            Level = reader.GetString(2),
                            Message = reader.IsDBNull(3) ? null : reader.GetString(3),
                            Exception = reader.IsDBNull(4) ? null : reader.GetString(4)
                        });
                    }
                }
            }

            return View(logs);
        }


        [Authorize(Roles = "Admin")]
        [HttpGet]
        public IActionResult AddUser()
        {
            return View(new ApplicationUser());
        }


        [Authorize(Roles = "Admin")]
        [HttpPost]
        public async Task<IActionResult> AddUser(ApplicationUser userModel, string selectedRole)
        {
            // Stupid validation rules removal 
            ModelState.Remove("CurrentPassword");
            ModelState.Remove("NewPassword");
            ModelState.Remove("ConfirmNewPassword");
            ModelState.Remove(nameof(userModel.RememberMe));



            if (!ModelState.IsValid)
            {
                TempData["ErrorMessage"] = "Please correct the errors in the form.";
                return View(userModel);
            }

            var user = new ApplicationUser
            {
                UserName = userModel.Email,
                Email = userModel.Email,
                FirstName = userModel.FirstName,
                LastName = userModel.LastName,
                City = userModel.City,
                PhoneNumber = userModel.PhoneNumber,
                AuthMethod = "Regular (Added by Admin)"
            };
            var result = await _userManager.CreateAsync(user, userModel.Password);


            if (result.Succeeded)
            {
                var roleResult = await _userManager.AddToRoleAsync(user, selectedRole);
                var confirmEmail = await _userManager.ConfirmEmailAsync(user, await _userManager.GenerateEmailConfirmationTokenAsync(user));

                TempData["SuccessMessage"] = "User added successfully.";
                _logger.LogInformation("Admin {AdminEmail} added new user {UserEmail} with role {Role}.", User.Identity.Name, user.Email, selectedRole);
            }
            else
            {
                TempData["ErrorMessage"] = "Error adding user: " + result.Errors.FirstOrDefault()?.Description;
                _logger.LogWarning("Admin {AdminEmail} Failed to add new user {UserEmail}. Errors: {Errors}", User.Identity.Name, user.Email, string.Join(", ", result.Errors));
                return View(userModel);
            }

            return RedirectToAction("UserManagement");
        }
    }
}

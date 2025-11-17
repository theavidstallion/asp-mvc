using Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.IO;

namespace Auth.Controllers
{
    public class AuthController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly EmailSender _emailSender;
        private readonly ILogger<AuthController> _logger;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, EmailSender emailSender, RoleManager<IdentityRole> roleManager, ILogger<AuthController> logger, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _roleManager = roleManager;
            _logger = logger;
            _configuration = configuration;
        }

        // Profile Page
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                await _signInManager.SignOutAsync();
                return RedirectToAction("Login");
            }

            return View(user);
        }

        [Authorize(Roles = "Admin,User")]
        [HttpPost]
        public async Task<IActionResult> Index(ApplicationUser userModel, IFormFile photo)
        {
            // Fetch the user
            var user = await _userManager.GetUserAsync(User);
            if (user == null) { return NotFound(); }

            try
            {
                // --- 1. STUPID VALIDATION & CLEANUP (For future development, better use nullable properties in model) ---

                // Remove validation for transient fields not submitted on this form
                ModelState.Remove(nameof(userModel.Password));
                ModelState.Remove(nameof(userModel.ConfirmPassword));
                ModelState.Remove(nameof(userModel.RememberMe));
                ModelState.Remove(nameof(userModel.AuthMethod));
                ModelState.Remove(nameof(photo));       // Damn thing, can alternatively set [BindNever] on the model property or set IFormFile as nullable

                // Flag for detecting update intent
                bool changingPassword = !string.IsNullOrEmpty(userModel.NewPassword);

                // Remove conditional validation errors for fields left blank when not changing password
                if (!changingPassword)
                {
                    ModelState.Remove(nameof(userModel.CurrentPassword));
                    ModelState.Remove(nameof(userModel.NewPassword));
                    ModelState.Remove(nameof(userModel.ConfirmNewPassword));
                }
                else if (string.IsNullOrEmpty(userModel.CurrentPassword))
                {
                    ModelState.AddModelError(nameof(userModel.CurrentPassword), "Current Password is required to change Ppassword.");
                }

                // Check if ANY validation errors exist
                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
                    _logger.LogError("Model State failed. {Errors}", string.Join(", ", errors));
                    userModel.Email = user.Email;
                    userModel.ProfilePictureUrl = user.ProfilePictureUrl;


                    return View(userModel);
                }

                bool profileUpdated = false;
                bool phoneNumberChanged = false; // Flag to check for 'NoChangeMessage' at the end


                // --- 2. FILE UPLOAD & PICTURE URL UPDATE ---
                if (photo != null && photo.Length > 0)
                {
                    var fileExtension = Path.GetExtension(photo.FileName);
                    var fileName = $"{user.Id}_profile{fileExtension}";
                    var uploadPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images", "profiles");
                    var filePath = Path.Combine(uploadPath, fileName);

                    Directory.CreateDirectory(uploadPath);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await photo.CopyToAsync(stream);
                    }

                    // Update the tracked entity's property
                    user.ProfilePictureUrl = $"/images/profiles/{fileName}";
                    profileUpdated = true;
                }

                // --- 3. PHONE NUMBER UPDATE (Requires SetPhoneNumberAsync) ---
                var existingPhoneNumberFromDb = await _userManager.GetPhoneNumberAsync(user);
                phoneNumberChanged = !string.Equals((userModel.PhoneNumber ?? string.Empty).Trim(), (existingPhoneNumberFromDb ?? string.Empty).Trim(), StringComparison.OrdinalIgnoreCase);

                if (phoneNumberChanged)
                {
                    // SetPhoneNumberAsync is special: it commits the phone change immediately and MUST BE checked for success
                    var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, userModel.PhoneNumber);
                    if (!setPhoneResult.Succeeded)
                    {
                        ModelState.AddModelError(string.Empty, "Error updating phone number.");
                        userModel.Email = user.Email;
                        return View(userModel);
                    }
                    profileUpdated = true;
                }


                _logger.LogInformation("Comparing names - DB: '{DbFirst}'/'{DbLast}'/'{DbCity}' vs Form: '{FormFirst}'/'{FormLast}'/'{FormCity}'",
                user.FirstName, user.LastName, user.City,
                userModel.FirstName, userModel.LastName, userModel.City);

                // --- 4. NAME/CITY UPDATE (Simple Property Mapping) ---
                if (user.FirstName != userModel.FirstName || user.LastName != userModel.LastName || user.City != userModel.City)
                {
                    _logger.LogInformation("Updating profile for user {UserEmail}: Name/City changed.", user.Email);
                    // Update the tracked entity (no database call yet)
                    user.FirstName = userModel.FirstName;
                    user.LastName = userModel.LastName;
                    user.City = userModel.City;
                    profileUpdated = true;
                }


                // --- 5. PASSWORD CHANGE LOGIC (Requires ChangePasswordAsync) ---
                if (changingPassword)
                {
                    var changePasswordResult = await _userManager.ChangePasswordAsync(user, userModel.CurrentPassword, userModel.NewPassword);

                    if (!changePasswordResult.Succeeded)
                    {
                        foreach (var error in changePasswordResult.Errors)
                        {
                            ModelState.AddModelError(string.Empty, error.Description);
                        }
                        userModel.Email = user.Email;
                        return View(userModel);
                    }
                    profileUpdated = true;
                }

                // --- 6. FINAL COMMIT (Saves Name/City/Picture URL) ---
                if (profileUpdated)
                {
                    // This final call saves all simple property changes (Name, City, ProfilePictureUrl) 
                    // that were NOT saved by SetPhoneNumberAsync or ChangePasswordAsync.
                    var updateResult = await _userManager.UpdateAsync(user);

                    if (!updateResult.Succeeded)
                    {
                        ModelState.AddModelError(string.Empty, "Error saving final profile changes.");
                        userModel.Email = user.Email;
                        return View(userModel);
                    }

                    await _signInManager.RefreshSignInAsync(user);
                    TempData["SuccessMessage"] = "Profile updated successfully! ✅";
                }
                else if (!phoneNumberChanged && !changingPassword)
                {
                    TempData["NoChangeMessage"] = "No changes were submitted. 🔄";
                }
            }
            catch (Exception ex)
            {
                // Log fatal error
                _logger.LogError(ex, "An unhandled exception occurred while updating profile for user {UserEmail}.", user.Email);
                throw;
            }

            return RedirectToAction("Index");
        }


        [HttpGet]
        public IActionResult Register()
        {
            return View(new ApplicationUser());
        }

        [HttpPost]
        public async Task<IActionResult> Register(ApplicationUser userModel)
        {
            try
            {
                // Remove validation for fields not used in registration form
                ModelState.Remove(nameof(userModel.RememberMe));
                ModelState.Remove(nameof(userModel.CurrentPassword));
                ModelState.Remove(nameof(userModel.NewPassword));
                ModelState.Remove(nameof(userModel.ConfirmNewPassword));
                ModelState.Remove(nameof(userModel.AuthMethod));

                if (ModelState.IsValid)
                {
                    var existingPhoneNumber = await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == userModel.PhoneNumber);
                    var existingUser = await _userManager.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email.ToLower() == userModel.Email.ToLower());


                    if (!ModelState.IsValid)
                    {
                        return View(userModel);
                    }


                    if (existingUser != null)
                    {

                        TempData["ErrorMessage"] = "An account with this email already exists. Please use the account recovery option here.";

                        return RedirectToAction("RecoverAccount", new { email = userModel.Email });
                    }

                    if (existingPhoneNumber != null)
                    {
                        var existingUserEmail = existingPhoneNumber.Email;
                        ModelState.AddModelError(nameof(userModel.PhoneNumber), "This phone number is already registered.");
                    }

                    

                    // Proceed with User Creation 
                    var user = new ApplicationUser
                    {
                        UserName = userModel.Email,
                        Email = userModel.Email,
                        PhoneNumber = userModel.PhoneNumber,
                        FirstName = userModel.FirstName,
                        LastName = userModel.LastName,
                        City = userModel.City,
                        AuthMethod = "Regular"
                    };

                    var result = await _userManager.CreateAsync(user, userModel.Password);


                    if (result.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var confirmationLink = Url.Action("ConfirmEmail", "Auth",
                            new { userId = user.Id, token = token }, protocol: HttpContext.Request.Scheme);

                        _logger.LogInformation("User {UserEmail} registered successfully. Sending email confirmation link.", user.Email);
                        var emailSubject = "Verify Email";
                        var emailBody = $"Please verify your email by clicking this link: <a href='{confirmationLink}'>Verify Email</a>";

                        try
                        {
                            // Direct call to the method on the concrete class
                            await _emailSender.SendEmailAsync(user.Email, emailSubject, emailBody);
                            TempData["SuccessMessage"] = "An email verification link has been sent. Please look for it in your email inbox.";
                        }
                        catch (Exception ex)
                        {
                            // Handle error, but keep the message vague for security
                            TempData["SuccessMessage"] = "There was an issue sending the email. Please try again signup later.";
                            _logger.LogError(ex, "Failed to send email confirmation to user {UserEmail}.", user.Email);
                            _userManager.DeleteAsync(user).Wait(); // Rollback user creation
                        }


                        return RedirectToAction("Login");
                    }

                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occured at Register action in Auth controller.");
                throw;
            }

            return View(userModel);
        }


        //Account Recovery

        [HttpGet]
        public IActionResult RecoverAccount(string email)
        {
            var model = new ApplicationUser { Email = email }; // Pre-populate the model
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> RecoverAccount(ApplicationUser userModel)
        {
            // Removing stupid validation errors for fields not used in this form
            ModelState.Remove(nameof(userModel.PhoneNumber));
            ModelState.Remove(nameof(userModel.ConfirmPassword));
            ModelState.Remove(nameof(userModel.CurrentPassword));
            ModelState.Remove(nameof(userModel.Email));
            ModelState.Remove(nameof(userModel.Password));
            ModelState.Remove(nameof(userModel.AuthMethod));
            ModelState.Remove(nameof(userModel.City));
            ModelState.Remove(nameof(userModel.FirstName));
            ModelState.Remove(nameof(userModel.LastName));

            var user = await _userManager.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == userModel.Email);

            if (user == null || !user.IsDeleted)
            {
                TempData["ErrorMessage"] = "Account recovery failed. Please check the email address.";
                return RedirectToAction(nameof(Login));
            }


            // Generate Token and URL
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Action(
                "ResetPassword",
                "Auth",
                new { userId = user.Id, token = token, recoveryFlag = "true" },
                protocol: HttpContext.Request.Scheme);

            // Send Email
            try
            {
                _emailSender.SendEmailAsync(
                    user.Email,
                    "Account Recovery",
                    $"Please recover your account by clicking this link: <a href='{callbackUrl}'>Recover Account</a>").Wait();
                TempData["SuccessMessage"] = "A recovery link has been sent to your email.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send account recovery email to user {UserEmail}.", user.Email);
                TempData["ErrorMessage"] = "Recovery failed: Could not send email. Please try again later.";
            }

            // Redirect to login page to display the message
            return RedirectToAction(nameof(Login));
        }




        // Email Confirmation Action
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            try
            {
                if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
                {
                    return NotFound();
                }
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return NotFound();
                }
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    TempData["SuccessMessage"] = "Email confirmed successfully! You can now log in.";
                    _logger.LogInformation("User {UserEmail} has confirmed their email successfully.", user.Email);
                    return RedirectToAction("Login");
                }
                else
                {
                    TempData["ErrorMessage"] = "Email confirmation failed. The link may be invalid or expired.";
                    _logger.LogError("Email confirmation failed for user {UserEmail}. Errors: {Errors} at ConfirmEmail action in Auth controller.", user.Email, string.Join(", ", result.Errors));
                    return RedirectToAction("Login");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occured at ConfirmEmail action in Auth controller.");
                throw;
            }
        }
        

        [HttpGet]
        public IActionResult Login ()
        {
            return View(new ApplicationUser());
        }

        [HttpPost]
        public async Task<IActionResult> Login (ApplicationUser userModel)
        {
            try
            {
                // Remove validation for fields not used in login form
                ModelState.Remove(nameof(userModel.PhoneNumber));
                ModelState.Remove(nameof(userModel.ConfirmPassword));
                ModelState.Remove(nameof(userModel.CurrentPassword));
                ModelState.Remove(nameof(userModel.NewPassword));
                ModelState.Remove(nameof(userModel.ConfirmNewPassword));
                ModelState.Remove(nameof(userModel.FirstName));
                ModelState.Remove(nameof(userModel.LastName));
                ModelState.Remove(nameof(userModel.City));
                ModelState.Remove(nameof(userModel.AuthMethod));

                var user = await _userManager.FindByEmailAsync(userModel.Email);

                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "No such user exists.");
                    return View(userModel);
                }

                bool isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(await _userManager.FindByEmailAsync(userModel.Email));


                if (!isEmailConfirmed)
                {
                    ModelState.AddModelError(string.Empty, "Email not confirmed. Please check your inbox.");
                    return View(userModel);
                }



                if (ModelState.IsValid)
                {
                    var result = await _signInManager.PasswordSignInAsync(
                        userModel.Email,
                        userModel.Password,
                        userModel.RememberMe,
                        lockoutOnFailure: false);

                    if (result.Succeeded)
                    {
                        TempData["SuccessMessage"] = "Login successful!";
                        _logger.LogInformation("User {UserEmail} logged in successfully.", userModel.Email);
                        return (RedirectToAction("Index", "Home"));
                    }

                    ModelState.AddModelError(string.Empty, "Invalid Login Attempt");
                    _logger.LogWarning("Invalid login attempt for user {UserEmail}.", userModel.Email);

                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occured at Login action in Auth controller.");
                throw;
            }
            return View(userModel);
        }
        
        // POST: /Auth/Logout - Logs the user out securely
        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }



        // ---------------------------------
        // Forget and Reset Password Actions
        // ---------------------------------



        [HttpGet]
        public IActionResult ForgetPassword()
        {
            return View(new ApplicationUser());
        }


        [HttpPost]
        public async Task<IActionResult> ForgetPassword(ApplicationUser userModel)
        {
            try
            {
                // Validation and User Retrieval

                // 1. Find the User
                var user = await _userManager.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == userModel.Email);

                if (user == null)
                {
                    ViewData["SuccessMessage"] = "No such user exists.";
                    return View(userModel);
                }

                if (_userManager.IsEmailConfirmedAsync(user).Result == false)
                {
                    ViewData["ErrorMessage"] = "Email not confirmed. Please verify email first.";
                    return View(userModel);
                }

                if (user.IsDeleted)
                {
                    _logger.LogWarning("Blocked password reset for soft-deleted user {Email}. Redirecting to recovery.", user.Email);
                    TempData["StatusMessage"] = "This account is inactive. Please use the Account Recovery feature to reactivate your account.";
                    return RedirectToAction("RecoverAccount", new {email = user.Email});
                }

                // 2. Generate Token and URL
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPassword", "Auth",
                    new { userId = user.Id, token = token }, protocol: HttpContext.Request.Scheme);

                // 3. Send Email using the directly injected class
                var emailSubject = "Password Reset Request";
                var emailBody = $"Please reset your password by clicking this link: <a href='{callbackUrl}'>Reset Password</a>";

                try
                {
                    // Direct call to the method on the concrete class
                    await _emailSender.SendEmailAsync(user.Email, emailSubject, emailBody);
                    ViewData["SuccessMessage"] = "A password reset link has been sent. Please look for it in your email inbox.";
                }
                catch (Exception)
                {
                    // Handle error, but keep the message vague for security
                    ViewData["SuccessMessage"] = "There was an issue sending the email. Please try again later.";
                }

            }
            catch (Exception ex)
            {
                var user = await _userManager.FindByEmailAsync(userModel.Email);
                _logger.LogError(ex, "Exception occured at Forget Password action in Auth Controller for user {UserEmail}", user.Email);
                throw;
            }
            return View(userModel);
        }


        [HttpGet]
        public async Task<IActionResult> ResetPassword(string token, string userId, string recoveryFlag)
        {
            try
            {
                bool isRecovery = !string.IsNullOrEmpty(recoveryFlag) &&
                      recoveryFlag.Equals("true", StringComparison.OrdinalIgnoreCase);
                // Check if the security parameters are present in the URL query string
                if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(userId))
                {
                    // This will display the error in the validation summary of the view.
                    ModelState.AddModelError(string.Empty, "Invalid or missing password reset link parameters.");
                }

                ViewData["Token"] = token;
                ViewData["UserId"] = userId;
                ViewData["IsRecovery"] = isRecovery;
            }
            catch (Exception ex)
            {
                var user = await _userManager.FindByIdAsync(userId);
                _logger.LogError(ex, "Exception occured at ResetPassword action in Auth controller for user {UserEmail}", user.Email);
                throw;
            }

            return View(new ApplicationUser());
        }



        // Validates token and updates the password.
        [HttpPost]
        public async Task<IActionResult> ResetPassword(ApplicationUser userModel, bool isRecovery)
        {
            try
            {
                // 1. Retrieve hidden fields from the form submission
                // NOTE: These fields must be present in the ResetPassword.cshtml as hidden inputs.
                var token = Request.Form["Token"].FirstOrDefault();
                var userId = Request.Form["UserId"].FirstOrDefault();

                // Removing stupid validation errors for fields not used in this form
                ModelState.Remove(nameof(userModel.PhoneNumber));
                ModelState.Remove(nameof(userModel.ConfirmPassword));
                ModelState.Remove(nameof(userModel.CurrentPassword));
                ModelState.Remove(nameof(userModel.Email));
                ModelState.Remove(nameof(userModel.Password));
                ModelState.Remove(nameof(userModel.AuthMethod));
                ModelState.Remove(nameof(userModel.City));
                ModelState.Remove(nameof(userModel.FirstName));
                ModelState.Remove(nameof(userModel.LastName));

                // Re-check for required security parameters
                if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(userId))
                {
                    ModelState.AddModelError(string.Empty, "Invalid token or user ID.");
                }

                // Check ModelState for New/Confirm Password validation errors (Format, Compare, Length)
                if (!ModelState.IsValid)
                {
                    // If validation fails, return the model and re-pass the security tokens to the view
                    ViewData["Token"] = token;
                    ViewData["UserId"] = userId;
                    ViewData["IsRecovery"] = isRecovery;
                    return View(userModel);
                }

                ApplicationUser user = null;

                if (isRecovery)
                {
                    user = await _userManager.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId);
                }
                else
                {
                    user = await _userManager.FindByIdAsync(userId);
                }
                    
                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "User not found.");
                    return View(userModel);
                }

                // Execute Password Reset
                // Identity validates the token's validity and ensures the new password meets complexity rules.
                var result = await _userManager.ResetPasswordAsync(user, token, userModel.NewPassword);

                if (result.Succeeded)
                {
                    if (isRecovery && user.IsDeleted)
                    {
                        user.IsDeleted = false;
                        await _userManager.UpdateAsync(user);
                        _logger.LogInformation("User {UserEmail} has recovered their account successfully via password reset.", user.Email);
                    }
                    
                    // Password reset successful!
                    TempData["SuccessMessage"] = "Your password has been reset successfully. You can now log in.";
                    return RedirectToAction(nameof(Login));
                }

                // 4. Handle Failure (Token invalid/expired, complexity not met)
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                // Re-pass the token/userId back to the view
                ViewData["Token"] = token;
                ViewData["UserId"] = userId;
            }
            catch (Exception ex)
            {
                var user = await _userManager.FindByIdAsync(userModel.Id);
                _logger.LogError(ex, "Failed to reset password for user {UserEmail}", user.Email);
                throw;
            }
            return View(userModel);
        }


        // Inactive Delete Actions

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> DeleteAccount(string currentPassword)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            if (string.IsNullOrEmpty(currentPassword))
            {
                TempData["ErrorMessage"] = "Password confirmation is required to delete the account.";
                return RedirectToAction("Index"); // Redirect to show error on the profile page
            }

            var passwordIsCorrect = await _userManager.CheckPasswordAsync(user, currentPassword);

            if (!passwordIsCorrect)
            {
                TempData["ErrorMessage"] = "Incorrect password. Account deletion aborted.";
                return RedirectToAction("Index"); // Redirect to show error on the profile page
            }


            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                await _signInManager.SignOutAsync();
                TempData["SuccessMessage"] = "Your account has been deleted successfully.";
                return RedirectToAction("Index", "Home");


            }
            TempData["ErrorMessage"] = "Error deleting account. Please ensure your password is correct.";
            return RedirectToAction("Index");
        }


        // Delete OAuth Account

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> DeleteOAuthAccount(string confirmText)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) { return NotFound(); }

            if (string.IsNullOrEmpty(confirmText) || confirmText.Trim().ToUpper() != "DELETE")
            {
                TempData["ErrorMessage"] = "You must type 'DELETE' to confirm.";
                return RedirectToAction("Index");
            }
            var result = await _userManager.DeleteAsync(user);

            if (result.Succeeded)
            {
                await _signInManager.SignOutAsync();
                TempData["SuccessMessage"] = "Your account has been deleted successfully. Goodbye!";
                return RedirectToAction("Index", "Home");
            }

            // 4. Failure Path
            TempData["StatusMessage"] = "Error deleting account due to a system error.";
            return RedirectToAction("Index");
        }




        // Social Login

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // 1. Set the redirect URL where Google sends the user back after successful login.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Auth", new { returnUrl });

            // 2. Configure the challenge properties (scheme and redirect URL).
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            // 3. Challenge the scheme (Redirect to Google).
            return Challenge(properties, provider);
        }


        // Receives the token from External Provider and processes the login locally.
        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            try
            {
                // Handle errors returned from the external provider
                if (remoteError != null)
                {
                    // Add error message and redirect to the standard login page
                    ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                    return RedirectToAction(nameof(Login));
                }

                // 1. Get the login information sent by the external provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    // Login info lost (e.g., cookie expired), redirect to login page
                    return RedirectToAction(nameof(Login));
                }

                
                // 2. Attempt to sign in the user if a local account is already linked (returning user)
                var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

                if (result.Succeeded)
                {
                    // Success: User is returning and already linked. Redirect to the homepage.
                    TempData["SuccessMessage"] = $"Welcome back! Logged in with {info.LoginProvider}.";
                    return RedirectToAction("Index", "Home");
                }

                var userEmail = info.Principal.FindFirstValue(ClaimTypes.Email);
                var userFetchByEmail = await _userManager.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == userEmail);

                if (userFetchByEmail != null && userFetchByEmail.IsDeleted)
                {
                    userFetchByEmail.IsDeleted = false;
                    var updateResult = await _userManager.UpdateAsync(userFetchByEmail);

                    if (updateResult.Succeeded)
                    {
                        await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
                        TempData["SuccessMessage"] = "Welcome back! Your account has been reactivated.";
                        _logger.LogInformation("User {UserEmail} has reactivated their account via external login.", userFetchByEmail.Email);
                        return RedirectToAction("Index", "Home");
                    }
                    else
                    {
                        TempData["ErrorMessage"] = "Account (Oauth) reactivation failed due to a system error.";
                        _logger.LogError("Failed to reactivate soft-deleted user {UserEmail} during external login. Errors: {Errors}", userFetchByEmail.Email, string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                        return RedirectToAction(nameof(Login));
                    }
                }




                // 3. Handle New User Registration (User authenticated but no local link found)
                if (result.IsLockedOut)
                {
                    // Handle locked out status if needed
                    return RedirectToAction("Lockout");
                }
                else
                {
                    // Get primary claims needed for provisioning the local account
                    var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                    var pictureClaim = info.Principal.FindFirstValue("picture") ?? info.Principal.FindFirstValue("avatar");

                    // Check if a local user already exists with this email but isn't linked to Google
                    var userByEmail = await _userManager.FindByEmailAsync(email);

                    if (userByEmail == null)
                    {
                        // PROVISIONING: User is completely new. Create a new ApplicationUser account.
                        var user = new ApplicationUser
                        {
                            UserName = email,
                            Email = email,
                            ProfilePictureUrl = pictureClaim,
                            // Retrieve custom profile data from Google claims
                            FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName),
                            LastName = info.Principal.FindFirstValue(ClaimTypes.Surname),
                            // PasswordHash will be null, making this a passwordless account
                            City = "Not Specified",
                            PhoneNumber = "", // Can be updated later in profile
                            AuthMethod = info.LoginProvider
                        };

                        var createResult = await _userManager.CreateAsync(user);

                        if (createResult.Succeeded)
                        {
                            var confirmResult = await _userManager.ConfirmEmailAsync(user, await _userManager.GenerateEmailConfirmationTokenAsync(user));
                            await _userManager.AddToRoleAsync(user, "User");

                            // Link the external login and sign the user in
                            await _userManager.AddLoginAsync(user, info);
                            await _signInManager.SignInAsync(user, isPersistent: false);

                            // Final Action: Redirect to the Profile page (Index) for initial details completion
                            TempData["StatusMessage"] = "Welcome! Please complete your profile details and save your settings.";
                            return RedirectToAction("Index", "Auth");
                        }
                        else { 
                            // Handle failure to create user (e.g., password complexity failure, though unlikely here)
                            foreach (var error in createResult.Errors)
                            {
                                ModelState.AddModelError(string.Empty, error.Description);
                            }
                            _logger.LogError("Failed to provision new external user {Email}. Errors: {Errors}",email, string.Join(", ", createResult.Errors.Select(e => e.Description)));
                        }
                    }
                    else
                    {
                        // EMAIL CONFLICT: User exists locally but tried to log in externally (need to link accounts)
                        // For simplicity in this setup, we will just prompt them to log in locally.
                        ModelState.AddModelError(string.Empty, "An account with this email already exists. Please log in with your password to link your external account.");
                    }

                    // If any error occurred during creation/linking, return to the Login page.
                    return RedirectToAction(nameof(Login));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception at OAuth in ExternalLoginCallback action in Auth controller.");
                throw;
            }
        }


        


        // Access Denied Page

        [HttpGet]
        public IActionResult AccessDenied()
        {
            // The framework will handle setting the HTTP status code (403 Forbidden).
            return View();
        }


        


    }
}

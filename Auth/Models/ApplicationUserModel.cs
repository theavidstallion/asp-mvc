using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Auth.Models
{
    public class ApplicationUser : IdentityUser
    {

        // INPUT FIELDS (Used for Register, Login, Change Password)

        [NotMapped]
        [Required(ErrorMessage = "Password is required.")] 
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{6,}$", ErrorMessage = "Password must contain an uppercase letter, a lowercase letter, a digit, and a special character.")]
        public string Password { get; set; } // Used for Register and Login input

        [NotMapped]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } // Used for Register validation

        
        [NotMapped]
        [DataType(DataType.Password)]
        [Display(Name = "Current Password")]
        public string CurrentPassword { get; set; } 

        [NotMapped]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "New Password must be at least 6 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{6,}$", ErrorMessage = "New Password must meet complexity requirements.")]
        public string NewPassword { get; set; } 

        [NotMapped]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage = "New passwords must match.")]
        public string ConfirmNewPassword { get; set; }

        [NotMapped]
        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }


        // IDENTITY FIELDS (Overridden for Annotations)
        [Required]
        [EmailAddress]
        public override string Email { get => base.Email; set => base.Email = value; }

        [Required]
        [Phone]
        public override string PhoneNumber { get => base.PhoneNumber; set => base.PhoneNumber = value; }

        // NEW FIELDS (For User Info)

        [MaxLength(50)]
        public string FirstName { get; set; }

        [MaxLength(50)]
        public string LastName { get; set; }

        [MaxLength(100)]
        public string City { get; set; }

        [MaxLength(50)]
        public string AuthMethod { get; set; } = "N/A"; // e.g., "Google", "Facebook", "Local"

        [MaxLength(100)]
        public string? RoleChangedBy { get; set; }

        [MaxLength(50)]
        public DateTimeOffset? RoleChangedDate { get; set; }

        [MaxLength(50)]
        public string? RoleChangedFrom { get; set; } // Previous role

        public bool IsDeleted { get; set; } = false; // Soft delete flag
    
        public string? DeletedBy { get; set; } // Who deleted the user

        public DateTimeOffset? DeletedAt { get; set; } // When the user was deleted

    }
}
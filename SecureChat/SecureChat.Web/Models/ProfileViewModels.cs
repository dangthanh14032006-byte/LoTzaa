using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace SecureChat.Web.Models
{
    public sealed class ProfileDetailsViewModel
    {
        public string Username { get; init; } = "";
        public string DisplayName { get; init; } = "";
        public string Bio { get; init; } = "";
        public string AvatarUrl { get; init; } = "";
        [Phone(ErrorMessage = "Số điện thoại không hợp lệ.")]
        public string PhoneNumber { get; set; } = "";

        [EmailAddress(ErrorMessage = "Địa chỉ email không hợp lệ.")]
        public string Email { get; set; } = "";

        [DataType(DataType.Date)]
        public DateTime? DateOfBirth { get; set; }

        [Required]
        public string Language { get; set; } = "vi";
    }

    public sealed class ProfileEditViewModel
    {
        [Required(ErrorMessage = "Vui lòng nhập tên hiển thị.")]
        [StringLength(40, ErrorMessage = "Tên hiển thị tối đa 40 ký tự.")]
        public string DisplayName { get; set; } = "";

        [StringLength(300, ErrorMessage = "Phần giới thiệu tối đa 300 ký tự.")]
        public string Bio { get; set; } = "";

        public IFormFile? Avatar { get; set; }

        public string AvatarUrl { get; set; } = "";
        [Phone(ErrorMessage = "Số điện thoại không hợp lệ.")]
        public string PhoneNumber { get; set; } = "";

        [EmailAddress(ErrorMessage = "Email không hợp lệ.")]
        public string Email { get; set; } = "";

        [DataType(DataType.Date)]
        public DateTime? DateOfBirth { get; set; }

        [Required]
        public string Language { get; set; } = "vi";
    }
}
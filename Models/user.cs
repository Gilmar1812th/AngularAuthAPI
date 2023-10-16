using System.ComponentModel.DataAnnotations;

namespace AngularAuthAPI.Models
{
    public class user
    {
        [Key]
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Token { get; set; }
        public string Role { get; set; }
        public string Email { get; set; }
        #nullable enable
        public string? RefreshToken { get; set; }
        #nullable disable
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
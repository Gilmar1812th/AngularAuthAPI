using System.ComponentModel.DataAnnotations;

namespace AngularAuthAPI.Models
{
    public class user
    {
        [Key] // primary key dataAnnotation
        public int Id { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? UserName { get; set; }
        public string? Password { get; set; }
        public string? Token { get; set; }
        public string? Role { get; set; }
        public string? Email { get; set; }
        // Resetar o token - Refresh Token - Token de atualização        
        #nullable enable
        public string? RefreshToken { get; set; }
        #nullable disable
        // Tempo de expiração
        public DateTime RefreshTokenExpiryTime { get; set; }
        // Redefinição de senha
        public string? ResetPasswordToken { get; set; }        
        // Depois de algum tempo o link de redefinição de senha expira (5 minutos)
        public DateTime ResetPassWordExpiry { get; set; }
    }
}
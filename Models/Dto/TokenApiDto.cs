namespace AngularAuthAPI.Models.Dto
{
    public class TokenApiDto
    {    
        public string AccessToken { get; set; } = string.Empty; // Token de acesso
        public string RefreshToken {get; set; } = string.Empty; // Token de atualização
    }
}
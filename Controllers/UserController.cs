using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using AngularAuthAPI.Models.Dto;
using AngularAuthAPI.UtilityService;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class UserController : ControllerBase
    {
        // injeção de dependência
        private readonly AppDbContext _authContext;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailservice;
        public UserController(AppDbContext appDbContext, IConfiguration configuration, IEmailService emailService)
        {
          _authContext = appDbContext;
          _configuration = configuration;
          _emailservice = emailService;
        }       

        [HttpPost("authenticate")] // nome da rota
        public async Task<IActionResult> Authenticate([FromBody] user userObj)
        {
          if(userObj == null)
            return BadRequest();

          var user = await _authContext.Users
            .FirstOrDefaultAsync(x => x.UserName == userObj.UserName);

          if((user == null) || (!PasswordHasher.VerifyPassWord(userObj.Password, user.Password)))
            return BadRequest(new { Message = "Usuário ou Senha inválidos"});

          user.Token = CreateJwt(user);
          var newAccessToken = user.Token;
          var newRefreshToken = CreateRefreshToken();
          user.RefreshToken = newRefreshToken;
          // Vai expirar o token de atualização após 5 dias
          user.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
          // preservar o token de ataulização no banco de dados
          await _authContext.SaveChangesAsync();

          return Ok(new TokenApiDto() {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken
          });
        }

        [HttpPost("register")] // nome da rota
        public async Task<IActionResult> RegisterUser([FromBody] user userObj)
        {
          if(userObj == null)
            return BadRequest();

          // Checar usuário
          if(await checkUserNameExistAsync(userObj.UserName))
            return BadRequest(new { Message = "Usuário já cadastrado!"});

          // Checar e-mail
          if(await checkEmailExistAsync(userObj.Email))
            return BadRequest(new { Message = "E-mail já cadastrado!"});

          // Checar se a senha de acesso esta no padrão
          var pass = CheckPasswordStrength(userObj.Password);
          if(!string.IsNullOrEmpty(pass))
            return BadRequest(new { Message = pass.ToString() });          

          userObj.Password = PasswordHasher.HasPassword(userObj.Password);
          userObj.Role = "User";
          userObj.Token = "";
          await _authContext.Users.AddAsync(userObj);
          await _authContext.SaveChangesAsync();
          return Ok(new 
          {
            Message = "Usuário Registrado!"
          }); 
        }

        #region checar se o usuário existe
        private Task<bool> checkUserNameExistAsync(string username)
          => _authContext.Users.AnyAsync(x => x.UserName == username);
        #endregion
        
        #region checar se o e-mail já existe
        private Task<bool> checkEmailExistAsync(string email)
          => _authContext.Users.AnyAsync(x => x.Email == email);
        #endregion
        
        #region validar o padrão da senha informada
        private string CheckPasswordStrength(string password) {
          StringBuilder sb = new StringBuilder();

          if(password.Length < 8)           
            sb.Append("A senha deve ter no minimo 8 caracteres" + Environment.NewLine);

          if(!(Regex.IsMatch(password,"[a-z]") && Regex.IsMatch(password, "[A-Z]")           
              && Regex.IsMatch(password, "[0-9]")))
            sb.Append("A senha deve ser alfanumérica" + Environment.NewLine);

          if(!Regex.IsMatch(password,"[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
            sb.Append("A senha deve conter um caracter especial" + Environment.NewLine);

          return sb.ToString();
       }
       #endregion

       #region criação do token
       private string CreateJwt(user user)
       {
          // manipulador de JWT Token
          var jwtTokenHandler = new JwtSecurityTokenHandler();
          // Chave secreta
          var key = Encoding.ASCII.GetBytes("veryverysecret......");
          // Criar as identidades
          var identity = new ClaimsIdentity(new Claim[]
          {
            // O Token terá
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(ClaimTypes.Name, $"{user.UserName}")
            // new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
          });

          // Credenciais - Chave de segurança - Criar assinatura
          var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

          // Descriptor de Token
          var tokenDescriptor = new SecurityTokenDescriptor
          {
            Subject = identity,
            // Token válido por um dia
            //Expires = DateTime.Now.AddDays(1),
            // Token válido por 10 segundos
            Expires = DateTime.Now.AddSeconds(10),
            SigningCredentials = credentials
          };

          // Criar Token
          var token = jwtTokenHandler.CreateToken(tokenDescriptor);

          // Retornar token criado criptografado
          // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
          return jwtTokenHandler.WriteToken(token);
       }
       #endregion

       #region RefreshTonken - Criar método de atualização do token 
       private string CreateRefreshToken() {
        var tokenBytes = RandomNumberGenerator.GetBytes(64);
        var refreshToken = Convert.ToBase64String(tokenBytes);

        var tokenInUser = _authContext.Users
          .Any(a => a.RefreshToken == refreshToken);

        if(tokenInUser)
        {
          return CreateRefreshToken();          
        }
        return refreshToken;
       }
       #endregion

       // Pegar as credenciais do token expirado
       private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
       {
          var key = Encoding.ASCII.GetBytes("veryverysecret......");
          var tokenValidationParameters = new TokenValidationParameters
          { 
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateLifetime = false
          };
          var tokenHandler = new JwtSecurityTokenHandler();
          SecurityToken securityToken;
          var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
          var jwtSecurityToken = securityToken as JwtSecurityToken;

          // checar algoritimo do token gerado
          if(jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
          {
            throw new SecurityTokenException("Este é um token inválido");
          }
          return principal;
       }

       [Authorize] // atributo - autorização - se não tiver token não tem acesso ao endpoint
       [HttpGet]
       public async Task<ActionResult<user>> GetAllUser()
       {
          return Ok(await _authContext.Users.ToListAsync());
       }

       // Atualizar token - vai gerar um novo token de acesso para o usuário
       [HttpPost("refresh")]
       public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
       {
          if(tokenApiDto is null)
            return BadRequest("Solicitação de cliente inválida");

          string AccessToken = tokenApiDto.AccessToken;
          string refreshToken = tokenApiDto?.RefreshToken;
          var principal = GetPrincipleFromExpiredToken(AccessToken);
          var username = principal.Identity.Name;
          var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == username);

          if(user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            return BadRequest("Solicitação Inválida");

          var newAccessToken = CreateJwt(user);
          var newRefreshToken = CreateRefreshToken();
          user.RefreshToken = newRefreshToken;
          await _authContext.SaveChangesAsync();

          return Ok(new TokenApiDto()
          {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
          });
       }

       // Envio de e-mail para redefinição de senha 
       [HttpPost("send-reset-email/{email}")]
       public async Task<IActionResult> SendEmail(string email)
       {
          // validar usuário - verificar se o usuário existe
          var user = await _authContext.Users.FirstOrDefaultAsync(a => a.Email == email);

          if(user is null)
          {
            return NotFound(new
            {
              StatusCode = 404,
              Message = "Email não Existe."
            });
          }

          var tokenBytes = RandomNumberGenerator.GetBytes(64);
          var emailToken = Convert.ToBase64String(tokenBytes);
          user.ResetPasswordToken = emailToken;
          // Link de e-mail para redefinição de senha irá expirar em 15 minutos
          user.ResetPassWordExpiry = DateTime.Now.AddMinutes(15);
          string from = _configuration["EmailSettings:From"];
          var emailModel = new EmailModel(email, "Reset Password", EmailBody.EmailStringBody(email, emailToken));
          // Envio do email
          _emailservice.SendEmail(emailModel);
          // Alterando o estado para modificado
          _authContext.Entry(user).State = EntityState.Modified;
          await _authContext.SaveChangesAsync();
          return Ok(new 
          {
            StatusCode = 200,
            Message = "Email Enviado."
          });
       }

       // clicou no link de redefinição de senha
       [HttpPost("reset-password")]
       public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
       {
          var newToken = resetPasswordDto.EmailToken.Replace(" ", "+");          
          var user = await _authContext.Users.AsNoTracking().FirstOrDefaultAsync(a => a.Email == resetPasswordDto.Email);          

          if(user is null)
          {
            return NotFound(new
            {
              StatusCode = 404,
              Message = "Usuário não Existe."
            });
          }

          var tokenCode = user.ResetPasswordToken;
          DateTime emailTokenExpiry = user.ResetPassWordExpiry;

          if(tokenCode != resetPasswordDto.EmailToken || emailTokenExpiry < DateTime.Now)
          {
            return BadRequest(new
            {
              StatusCode = 400,
              Message = "Link de redefinição inválido, solicite outro link."
            });
          }

          user.Password = PasswordHasher.HasPassword(resetPasswordDto.NewPassword);
          // marcar como modificado
          _authContext.Entry(user).State = EntityState.Modified;
          await _authContext.SaveChangesAsync();
          return Ok(new
          {
            StatusCode = 200,
            Message = "Senha resetada com sucesso."
          });
       }
    }
}
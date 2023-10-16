using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.RegularExpressions;
using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using AngularAuthAPI.Models.Dto;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
          _authContext = appDbContext;
        }       

        [HttpPost("authenticate")]
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
          await _authContext.SaveChangesAsync();

          return Ok(new TokenApiDto() {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken
          });
        }

        [HttpPost("register")]
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

          // Checar senha de acesso
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

       private Task<bool> checkEmailExistAsync(string email)
          => _authContext.Users.AnyAsync(x => x.Email == email);

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

       private string CreateJwt(user user)
       {
          var jwtTokenHandler = new JwtSecurityTokenHandler();
          var key = Encoding.ASCII.GetBytes("veryverysecret......");
          var identity = new ClaimsIdentity(new Claim[]
          {
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(ClaimTypes.Name, $"{user.UserName}")
          });

          var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

          var tokenDescriptor = new SecurityTokenDescriptor
          {
            Subject = identity,
            // Token válido por um dia
            //Expires = DateTime.Now.AddDays(1),
            // Token válido por 10 segundos
            Expires = DateTime.Now.AddSeconds(10),
            SigningCredentials = credentials
          };

          var token = jwtTokenHandler.CreateToken(tokenDescriptor);

          return jwtTokenHandler.WriteToken(token);
       }

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

          if(jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
          {
            throw new SecurityTokenException("Este é um token inválido");
          }
          return principal;          
       }

       [Authorize]
       [HttpGet]
       public async Task<ActionResult<user>> GetAllUser()
       {
          return Ok(await _authContext.Users.ToListAsync());
       }

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
    }
}
using System.Text;
using AngularAuthAPI.Context;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// 1) resolvendo problema de api origem na chamada da API pelo front-end
builder.Services.AddCors(options =>
{
    // adicionando uma política
    options.AddPolicy("MyPolicy", builder => {
        // aceitar conexão de qualquer origem
        // aceitar qualquer método
        // aceitar qualquer header
        builder.AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader();
    });
});

// adicionando serviço do banco de dados
builder.Services.AddDbContext<AppDbContext>(option => 
{
    // Usando Sql Server, mas poderia ser outro banco de dados    
    option.UseSqlServer(builder.Configuration.GetConnectionString("SqlServerConnStr"));
});
// Serviço de envio de e-mail
builder.Services.AddScoped<IEmailService, emailService>();

// Adicionar o serviço para Token
builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        // Informar que o token deve validar a chave secreta
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("veryverysecret......")),
        ValidateAudience = false,
        ValidateIssuer = false
        //ClockSkew = TimeSpan.Zero (Token estará autenticado por 10 segundos)
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline, somente no ambiente de desenvolvimento
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// 2) resolvendo problema de api origem na chamada da API pelo front-end
// adicionando pipeline
app.UseCors("MyPolicy");

// 3) Autenticação
app.UseAuthentication();

// 4) Autorização
app.UseAuthorization();

app.MapControllers();

app.Run();

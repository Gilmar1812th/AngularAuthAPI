using System;
using System.Net;
using MimeKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using AngularAuthAPI.Models;

namespace AngularAuthAPI.UtilityService
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;
        public EmailService(IConfiguration configuration)
        {
            _config = configuration;
        }

        public void SendEmail(EmailModel emailModel)
        {
            // pacote para usar enviar o email
            var emailMessage = new MimeMessage();
            // pegar o que esta em from do appsettings.json
            var from = _config["EmailSettings:From"];            
            emailMessage.From.Add(new MailboxAddress("Lets Program", from));
            emailMessage.To.Add(new MailboxAddress(emailModel.To, emailModel.To));
            emailMessage.Subject = emailModel.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = string.Format(emailModel.Content)
            };

            // usando SMTP            
            using (var client = new SmtpClient())
            {
                try
                {
                    // true = SSL                    
                    client.Connect(_config["EmailSettings:SmtpServer"], 465, true);
                    client.Authenticate(_config["EmailSettings:From"], _config["EmailSettings:Password"]);
                    client.Send(emailMessage);
                    client.Disconnect(true);
                    
                    //client.EnableSsl = true;
                    /* apagar 
                    client.Connect(_config["EmailSettings:SmtpServer"], 465, SecureSocketOptions.SslOnConnect);
                    client.Authenticate(_config["EmailSettings:Username"], _config["EmailSettings:Password"]);
                    client.Send(emailMessage);
                    client.Disconnect(true); apagar*/
                }
                catch (Exception ex)
                {
                    throw; 
                }
                finally
                {
                    client.Disconnect(true);
                    client.Dispose();
                }
            }
        }
    }
}
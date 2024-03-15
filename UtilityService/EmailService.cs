using System;
using AngularAuthAPI.Models.Dto;
using MimeKit;

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
            emailMessage.From.Add(new MailBoxAddress("Lets Program", from));
            emailMessage.To.Add(new  MailBoxAddress(emailModel.To, emailModel.To));
            emailMessage.Subject = emailModel.Subject;
            emailModel.Body = new TextPart(MimeKit.Text.TextFormat.Html)
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
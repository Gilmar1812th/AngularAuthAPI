using AngularAuthAPI.Models.Dto;

namespace AngularAuthAPI.UtilityService
{
    public interface IEmailService
    {
         void SendEmail(EmailModel emailModel);
    }
}
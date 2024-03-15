using AngularAuthAPI.Models.Dto;

namespace AngularAuthAPI.Models.Dto
{
    public class EmailModel
    {
        // Propriedades
        public string To { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }

        // construtor
        public EmailModel(string to, string subject, string content)
        {
            To = to;
            Subject = subject;
            Content = content;
        }        
    }
}
using System;

namespace AngularAuthAPI.Helpers
{
    public static class EmailBody
    {
        public static string EmailStringBody(string email,string emailToken)
        {
            return $@"<html>
                     <head>
                   </head>
                <body style=""margin:0;font-family: Arial, Helvetica, sans-serif;"">
               <div style=""height: auto;background: linear-gradient(to top, #c9c9ff 50%, #6e6ef6 90%) no-repeat;"">
            <div style=""width:400px; height:auto;padding:15px; background:#fff;position:absolute;top:20%;left:50%;transform:translate(-50%,-20%"">
            <div>
              <h1>Redefinir sua senha</h1>
              <hr>
                <p style=""color:grey"">Você está recebendo este e-mail porque solicitou uma redefinição de senha da sua conta Let's Program.</p>

                <p style=""color:grey"">Por favor, clique no botão abaixo para escolher uma nova senha.</p>

              <a href=""http://localhost:4200/reset?email={email}&code={emailToken}"" target=""_blank"" style=""background:#0d6efd;padding:10px;border:none;
              color:white;border-radius:4px;display:block;margin:0 auto;width:50%;text-align:center;text-decoration:none"">Redefinir senha</a><br>

              <p>Kind Regards,<br><br>
                Let's Program</p>
              </div>
          </div>
        </div>
      </body>
        </html>";
        }
    }
}


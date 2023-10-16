using System.Security.Cryptography;
using System.Text;

namespace AngularAuthAPI.Helpers
{
    public class PasswordHasher
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();        
        private static readonly int SaltSize = 16;
        private static readonly int HasSize = 20;
        private static readonly int Iterations = 10000;

        public static string HasPassword(string password)
        {
            //var randomNumber = new byte[32];
            //string refreshToken = "";

            byte[] salt;
            rng.GetBytes(salt = new byte[SaltSize]);
            var key = new Rfc2898DeriveBytes(password, salt, Iterations);
            var hash = key.GetBytes(HasSize);

            var hasBytes = new byte[SaltSize + HasSize];
            Array.Copy(salt, 0, hasBytes, 0, SaltSize);
            Array.Copy(hash, 0, hasBytes, SaltSize, HasSize);

            var base64Hash = Convert.ToBase64String(hasBytes);

            return base64Hash;

            /*using (var rng = RandomNumberGenerator.Create())
            {
                 rng.GetBytes(randomNumber);
                 refreshToken = Convert.ToBase64String(randomNumber);
                 return refreshToken;
            }*/            
        }

        public static bool VerifyPassWord(string password, string base64Hash) {
            var hashBytes = Convert.FromBase64String(base64Hash);

            var salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            var key = new Rfc2898DeriveBytes(password, salt, Iterations);
            byte[] hash = key.GetBytes(HasSize);
            
            for (var i = 0; i < HasSize; i++)
            {
                if(hashBytes[i + SaltSize] != hash[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
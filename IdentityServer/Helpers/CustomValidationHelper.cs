using System.Linq;
namespace IdentityServer.Helpers
{
    public static class CustomValidationHelper
    {
        public static bool IsAcceptableName(string name)
        {
            int minimumNameLength = 3;
            int maximumNameLength = 20;

            return name.Length >= minimumNameLength && name.Length <= maximumNameLength;
        }

        public static bool IsAcceptablePassword(string password)
        {
            
            int minimumPasswordLength = 8;

            return password.Length >= minimumPasswordLength;
        }
    }

}
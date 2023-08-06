namespace IdentityServer.Models
{
    public class LoginResult
    {
        public string Token { get; set; }
        public DateTime Expiry { get; set; }
    }
}

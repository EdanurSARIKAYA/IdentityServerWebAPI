using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models
{
    public class Users
    {
        [Key]
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

    }
}
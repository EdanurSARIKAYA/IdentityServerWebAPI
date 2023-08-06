using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models
{
    public class Users
    {
        [Key]
        public string username { get; set; }
        public string password { get; set; }

    }
}

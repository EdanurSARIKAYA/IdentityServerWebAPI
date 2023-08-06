
using IdentityServer.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IdentityServer.Controllers
{
    //Controllerbase handles HTTP requests.
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : ControllerBase
    {

        private readonly AppDbContext _appDbContext;
        private readonly IConfiguration _configuration;

        private AuthenticationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        public AuthenticationController(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }



        [HttpPost("register")]
        public IActionResult Register(string Username, string Password)
        {
            if(!IsAcceptableName(Username) && !IsAcceptablePassword(Password))
            {
                return BadRequest("You must enter the username and password according to the specified rules.");
            }

            if(_appDbContext.Users.Any(x => x.username == Username))
            {
                return BadRequest("This username has already been taken.");
            }

            else
            {
                Byte[] byteOfPassword;
                Byte[] byteOfHashedPassword;
                MD5 md5;

                md5 = new MD5CryptoServiceProvider();
                byteOfPassword = ASCIIEncoding.Default.GetBytes(Password);
                byteOfHashedPassword = md5.ComputeHash(byteOfPassword);


                Users user = new Users()
                {
                    username = Username,
                    password = BitConverter.ToString(byteOfHashedPassword)
                };

                _appDbContext.Users.Add(user);
                _appDbContext.SaveChanges();

                return Ok("Your registration has been successfully completed.");
            } 
            
        }





        [HttpPost("login")]
        public IActionResult Login(string Username, string Password) 
        {
            if(!IsAcceptableName(Username) && !IsAcceptablePassword(Password))
            {
                return BadRequest("You must enter the username and password according to the specified rules.");
            }


            Byte[] byteOfPassword;
            Byte[] byteOfHashedPassword;
            MD5 md5;

            md5 = new MD5CryptoServiceProvider();
            byteOfPassword = ASCIIEncoding.Default.GetBytes(Password);
            byteOfHashedPassword = md5.ComputeHash(byteOfPassword);


            Users user = _appDbContext.Users.SingleOrDefault(x => x.username == Username && x.password == BitConverter.ToString(byteOfHashedPassword));
            if(user != null)
            {
                var tokenResult = GenerateToken(Username);
                return Ok(tokenResult);
            }

            return BadRequest("Username or password is incorrect.");  
        }

        private LoginResult GenerateToken(string Username)
        {
            var claims = GenerateUserClaims(Username);

            var key=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiry = DateTime.Now.AddMinutes(60);

            var token= new JwtSecurityToken(_configuration["Jwt: Issuer"], _configuration["Jwt:Audience"], claims, expires:expiry,
                signingCredentials: signIn);

            LoginResult loginresult = new()
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiry = expiry
            };

            return loginresult;
        }


        private Claim[] GenerateUserClaims(string Username)
        {
            return new[] {
                new Claim(JwtRegisteredClaimNames.Sub,_configuration["Jwt: Subject"]),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,DateTime.UtcNow.ToString()),
                new Claim("Username", Username),
            };
        }

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

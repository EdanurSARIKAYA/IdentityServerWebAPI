using IdentityServer.Helpers;
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

        public AuthenticationController(AppDbContext appDbContext, IConfiguration configuration)
        {
            _appDbContext = appDbContext;
            _configuration = configuration;
        }


        [HttpPost("register")]
        public IActionResult Register([FromBody] Users model)
        {
            if (!CustomValidationHelper.IsAcceptableName(model.UserName) || !CustomValidationHelper.IsAcceptablePassword(model.Password))
            {
                return BadRequest("You must enter the username and password according to the specified rules.");
            }

            if (_appDbContext.Users.Any(x => x.UserId == model.UserId))
            {
                return BadRequest("This username has already been taken.");
            }

            Byte[] byteOfPassword;
            Byte[] byteOfHashedPassword;
            MD5 md5;

            md5 = new MD5CryptoServiceProvider();
            byteOfPassword = ASCIIEncoding.Default.GetBytes(model.Password);
            byteOfHashedPassword = md5.ComputeHash(byteOfPassword);

            Users user = new Users()
            {
                UserId = model.UserId,
                UserName = model.UserName,
                Password = BitConverter.ToString(byteOfHashedPassword)
            };

            _appDbContext.Users.Add(user);
            _appDbContext.SaveChanges();

            return Ok("Your registration has been successfully completed.");
        }



        [HttpPost("login")]
        public IActionResult Login([FromBody] Users model)
        {
            if (!CustomValidationHelper.IsAcceptableName(model.UserName) || !CustomValidationHelper.IsAcceptablePassword(model.Password))
            {
                return BadRequest("You must enter the username and password according to the specified rules.");
            }

            Byte[] byteOfPassword;
            Byte[] byteOfHashedPassword;
            MD5 md5;

            md5 = new MD5CryptoServiceProvider();
            byteOfPassword = ASCIIEncoding.Default.GetBytes(model.Password);
            byteOfHashedPassword = md5.ComputeHash(byteOfPassword);


            Users user = _appDbContext.Users.SingleOrDefault(x => x.UserId == model.UserId);

            if (user != null)
            {
                var tokenResult = GenerateToken(model.UserName);
                return Ok(tokenResult);
            }

            return BadRequest("Username or password is incorrect.");
        }


        private LoginResult GenerateToken(string Username)
        {
            var claims = GenerateUserClaims(Username);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"]));

            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiry = DateTime.Now.AddMinutes(60);

            var token = new JwtSecurityToken(_configuration["JwtSettings:Issuer"], _configuration["JwtSettings:Audience"], claims, expires: expiry,
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
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,DateTime.UtcNow.ToString()),
                new Claim("Username", Username),
            };
        }




    }
}
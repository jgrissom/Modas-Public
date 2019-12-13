using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Modas.Models;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Modas.Controllers
{
    [Route("api/[controller]")]
    public class TokenController : Controller
    {
        private UserManager<AppUser> userManager;
        private SignInManager<AppUser> signInManager;
        private IConfiguration _config;

        public TokenController(UserManager<AppUser> userMgr, SignInManager<AppUser> signInMgr, IConfiguration config)
        {
            _config = config;
            userManager = userMgr;
            signInManager = signInMgr;
        }

        [HttpPost, AllowAnonymous]
        public async Task<object> CreateToken([FromBody]LoginModel login)
        {
            // default response 401 Unauthorized
            IActionResult response = Unauthorized();
            if (ModelState.IsValid)
            {
                AppUser user = await userManager.FindByEmailAsync(login.Username);
                if (user != null)
                {
                    await signInManager.SignOutAsync();
                    Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(user, login.Password, false, false);
                    if (result.Succeeded)
                    {
                        // Check for role
                        if (await userManager.IsInRoleAsync(user, _config["Jwt:Role"]))
                        {
                            var tokenString = BuildToken(user);
                            response = Ok(new { token = tokenString });
                        }
                        else
                        {
                            // 403 Forbidden
                            response = Forbid();
                        }
                    }
                }
            }
            return response;
        }

        private string BuildToken(AppUser user)
        {
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                null, // issuer
                null, // audience
                claims,
                expires: DateTime.Now.AddDays(Int16.Parse(_config["Jwt:ValidFor"])),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public class LoginModel
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }
    }
}

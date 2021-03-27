using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace OAuthProxy.Auth
{
    /// <summary>
    /// Creates the JWT token.
    /// </summary>
    public class JwtTokenCreator
    {
        private JwtTokenCreatorConfig config;

        public JwtTokenCreator(JwtTokenCreatorConfig config)
        {
            this.config = config;
        }

        public RedirectResult GenerateTokenAndRedirect(string userId, Controller controller)
        {
            var token = GenerateToken(controller);

            var encodedToken = HttpUtility.UrlEncode(token);

            var redirectUrl = this.config.RedirectUrl.Replace("{TOKEN}", encodedToken);

            return controller.Redirect(redirectUrl);
        }

        public string GenerateToken(Controller controller)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(this.config.Secret));

            var myIssuer = config.Issuer;
            var myAudience = config.Audience;

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                     new Claim(ClaimTypes.NameIdentifier, controller.User.ToString()),
                }),

                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = myIssuer,
                Audience = myAudience,
                SigningCredentials = new SigningCredentials(mySecurityKey, SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

    public class JwtTokenCreatorConfig
    {
        public string Issuer { get; set; } = "https://korto.com/identityserver";

        public string Audience { get; set; } = "https://korto.com/blazorapp";

        public string Secret { get; set; } = "asdv234234^&%&^%&^hjsdfb2%%%";

        public string RedirectUrl { get; set; } = "https://localhost:44316/admin2/user?token={TOKEN}";
    }
}

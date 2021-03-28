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

namespace OAuthProxy
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

        public RedirectResult GenerateTokenAndRedirect(string userName, Controller controller)
        {
            var token = GenerateToken(controller);

            var encodedToken = HttpUtility.UrlEncode(token);

            var logoutUrl = $"{controller.Request.Scheme}://{controller.Request.Host.Value}/user/Logout";

            var encodedLogoutUrl = HttpUtility.UrlEncode(logoutUrl);

            var encodeduserName = HttpUtility.UrlEncode(userName);

            var redirectUrl = $"{this.config.RedirectUrl.TrimEnd('/')}/?token={encodedToken}&logouturl={encodedLogoutUrl}&username={encodeduserName}";

            return controller.Redirect(redirectUrl);
        }

        public string GenerateToken(Controller controller)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(this.config.Secret))
            {
                KeyId = this.config.Kid,
            };

            var myIssuer = config.Issuer;
            var myAudience = config.Audience;

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("provider", controller.User.Identity.AuthenticationType),
                    new Claim(ClaimTypes.NameIdentifier, controller.User.Claims.FirstOrDefault(c=>c.Type == ClaimTypes.NameIdentifier)?.Value),
                    new Claim(ClaimTypes.Email, controller.User.Claims.FirstOrDefault(c=>c.Type == ClaimTypes.Email)?.Value),
                    new Claim(ClaimTypes.GivenName, controller.User.Claims.FirstOrDefault(c=>c.Type == ClaimTypes.GivenName)?.Value),
                    new Claim(ClaimTypes.Name, controller.User.Claims.FirstOrDefault(c=>c.Type == ClaimTypes.Name)?.Value),
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
        public string Issuer { get; set; } = "https://oauthproxy.com/identityserver";

        public string Audience { get; set; } = "https://oauthproxy.com/audience";

        public string Secret { get; set; } = "asdv234234^&%&^%&^hjsdfb2%%%DDAAxy";

        /// <summary>
        /// Keyidentifier ofthe proxy instance.
        /// </summary>
        public string Kid { get; set; }

        public string RedirectUrl { get; set; } = "https://localhost:44316/admin2/user?token={TOKEN}";
    }
}

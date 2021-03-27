using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OAuthProxy.Auth;
using OidcApp.Models;

namespace OidcApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> logger;

        private JwtTokenCreator jwtTokenCreator;

        public HomeController(ILogger<HomeController> logger, JwtTokenCreator jwtTokenCreator)
        {
            this.logger = logger;
            this.jwtTokenCreator = jwtTokenCreator;
        }

        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated && User.Claims.Any(x => x.Type == System.Security.Claims.ClaimTypes.Name))
            {
                var res = jwtTokenCreator.GenerateTokenAndRedirect(User.Identity.Name, this);
                if (res != null)
                    return res;
            }
            
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}

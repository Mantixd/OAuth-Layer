using Microsoft.AspNetCore.Mvc;
using OAuth_Layer.dbContext;
using OAuth_Layer.Models;
using System.Diagnostics;

namespace OAuth_Layer.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private IConfiguration _configuration;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }
        private string GenerateJSONWebToken()
        {
            string rt = CreateRT();
            SetRTCookie(rt);

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MynameisJamesBond007"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "https://www.yogihosting.com",
                audience: "https://www.yogihosting.com",
                expires: DateTime.Now.AddMinutes(1),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Index(Login login)
        { 
            dbConnection dbcon = new dbConnection(_configuration);
            UserData data = dbcon.LoginCheck(login);
            if (data.firstname == null)
            {
                return Error();
            } else
            {
                ViewData["clientData"] = data;
                return View("Profile");
            }
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
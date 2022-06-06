using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using OAuth_Layer.dbContext;
using OAuth_Layer.Models;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

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
        private string GenerateJSONWebToken(string userid, Claim[] claims)
        {
            string rt = CreateRT();
            SetRTCookie(rt);

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("RicardoPerezxd85$"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "ricardoperez",
                audience: "ricardoperez",
                expires: DateTime.Now.AddMinutes(1),
                signingCredentials: credentials,
                claims: claims
                );

            string tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            string connectionString = _configuration.GetConnectionString("MyConnection");
            SqlConnection con = new SqlConnection(connectionString);
            SqlCommand com = new SqlCommand("SpRefreshToken", con);
            com.CommandType = CommandType.StoredProcedure;
            com.Parameters.AddWithValue("@userid", userid);
            com.Parameters.AddWithValue("@token", tokenString);
            com.Parameters.AddWithValue("@expirationdate", token.ValidTo.Date);
            con.Open();
            com.ExecuteNonQuery();
            con.Close();

            return tokenString;
        }
        private bool CheckCookieValue(string cookieValue)
        {
            // Check the cookie value with stored in the db. If No match then it is forged cookie so return false.
            return true;
        }
        public IActionResult RefreshToken(string userid, string role)
        {
            string cookieValue = Request.Cookies["refreshToken"];

            // If cookie is expired then it will give null
            if (cookieValue == null)
                return RedirectToAction("Index");

            // If cookie value is not the same as stored in db it is Hacking Attempt
            if (!CheckCookieValue(cookieValue))
                return RedirectToAction("Index");

            var claims = new[] {
                    new Claim(ClaimTypes.Role, role)
            };

            var tokenString = GenerateJSONWebToken(userid, claims);
            return RedirectToAction("GetUserData", new { token = tokenString, userid = userid });
        }
        private string CreateRT()
        {
            var randomNumber = new byte[32];
            using (var generator = new RNGCryptoServiceProvider())
            {
                generator.GetBytes(randomNumber);
                string token = Convert.ToBase64String(randomNumber);
                return token;
            }
        }

        private void SetRTCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7), // one week expiry time
            };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        public async Task<IActionResult> GetUserData(string token, string userid, string role)
        {
            UserData data = new UserData();

            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using (var response = await httpClient.GetAsync("https://localhost:7290/Profile?userid=" + Convert.ToInt32(userid)+""))
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        string apiResponse = await response.Content.ReadAsStringAsync();
                        data = JsonConvert.DeserializeObject<UserData>(apiResponse);
                        ViewData["clientData"] = data;
                    }

                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        return RedirectToAction("RefreshToken", new { userid = userid, role = role });
                    }
                }
            }

            return View("Profile");
        }
        private void SetJWTCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddHours(3),
            };
            Response.Cookies.Append("jwtCookie", token, cookieOptions);
        }

        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Index(Login login)
        { 
            string connectionString = _configuration.GetConnectionString("MyConnection");
            SqlConnection con = new SqlConnection(connectionString);
            SqlCommand com = new SqlCommand("SpUserExists", con);
            com.CommandType = CommandType.StoredProcedure;
            com.Parameters.AddWithValue("@username", login.username);
            com.Parameters.AddWithValue("@password", login.password);
            String userid = "";
            String role = "";
            con.Open();
            using (SqlDataReader oReader = com.ExecuteReader())
            {
                while (oReader.Read())
                {
                    userid = oReader["UserId"].ToString();
                    role = oReader["Role"].ToString();
                }

                con.Close();
            }
            if (userid == "0")
            {
                ViewData["errorMessage"] = "Invalid username and password.";
                return View("Index");
            } else
            {
                var claims = new[] {
                    new Claim(ClaimTypes.Role, role)
                };
                var accessToken = GenerateJSONWebToken(userid, claims);
                SetJWTCookie(accessToken);
                return RedirectToAction("GetUserData", new { token = accessToken, userid = userid, role = role });
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
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuth_Layer.Models;
using System.Data;
using System.Data.SqlClient;

namespace OAuth_Layer.Controllers
{
    [Route("[controller]")]
    [ApiController]
    [Authorize(Roles = "Administrator")]
    public class ProfileController : ControllerBase
    {
        private readonly ILogger<ProfileController> _logger;
        private IConfiguration _configuration;

        public ProfileController(ILogger<ProfileController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        [HttpGet]
        public UserData Get(string userid)
        {
            string connectionString = _configuration.GetConnectionString("MyConnection");
            SqlConnection con = new SqlConnection(connectionString);
            SqlCommand com = new SqlCommand("SpGetUserData", con);
            com.CommandType = CommandType.StoredProcedure;
            com.Parameters.AddWithValue("@userid", userid);
            UserData user = new UserData();
            con.Open();
            using (SqlDataReader oReader = com.ExecuteReader())
            {
                while (oReader.Read())
                {
                    user.firstname = oReader["firstname"].ToString();
                    user.lastname = oReader["lastname"].ToString();
                    user.email = oReader["email"].ToString();
                }

                con.Close();
            }
            return user;
        }
    }
}

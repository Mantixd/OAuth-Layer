using OAuth_Layer.Models;
using System.Data;
using System.Data.SqlClient;
using Microsoft.Extensions.Configuration;

namespace OAuth_Layer.dbContext
{
    public class dbConnection
    {
        private readonly IConfiguration Configuration;
        public dbConnection(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        

        public UserData LoginCheck(Login ad)
        {
            string connectionString = this.Configuration.GetConnectionString("MyConnection");
            SqlConnection con = new SqlConnection(connectionString);
            SqlCommand com = new SqlCommand("SpGetUserData", con);
            com.CommandType = CommandType.StoredProcedure;
            com.Parameters.AddWithValue("@username", ad.username);
            com.Parameters.AddWithValue("@password", ad.password);
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

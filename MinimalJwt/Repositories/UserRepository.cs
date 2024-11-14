using MinimalJwt.Models;

namespace MinimalJwt.Repositories;

public class UserRepository
{
    public static List<User> Users = new()
    {
        new()
        {
            Username = "emcp_admin",
            EmailAddress = "emcp04@gmail.com",
            Password = "MyPassword$",
            GivenName = "Emcp",
            Surname = "Emmanuel",
            Role = "Administrator"
        },
        new()
        {
            Username = "susana_standard",
            EmailAddress = "susana@gmail.com",
            Password = "MyPassword$",
            GivenName = "Susi",
            Surname = "Morenita",
            Role = "Standard"
        }
    };
}

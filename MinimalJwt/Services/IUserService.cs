using MinimalJwt.Models;

namespace MinimalJwt.Services;

public interface IUserService
{
    User Get(UserLogin userLogin);
}
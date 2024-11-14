using MinimalJwt.Models;

namespace MinimalJwt.Services;

public interface IMovieService
{
    Movie Create(Movie movie);
    bool Delete(int id);
    Movie Get(int id);
    List<Movie> List();
    Movie Update(Movie movie);
}
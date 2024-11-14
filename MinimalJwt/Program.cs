using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MinimalJwt.Models;
using MinimalJwt.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSwaggerGen(opt =>
{
    opt.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Description = "Bearer Authentication with JWT Token",
        Type = SecuritySchemeType.Http
    });
    opt.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            new List<string>()
        }
    });
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(opt =>
{
    opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateActor = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});
builder.Services.AddAuthorization();

//Register services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSingleton<IMovieService, MovieService>();
builder.Services.AddSingleton<IUserService, UserService>();

var app = builder.Build();
app.UseSwagger();
app.UseAuthorization();
app.UseAuthentication();

app.MapGet("/", () => "Online");

//Endpoints mapping
app.MapPost("/login",
    (UserLogin user, IUserService service) => Login(user, service));

app.MapPost("/create",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
    (Movie movie, IMovieService movieService) => Create(movie, movieService));

app.MapGet("/get",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Standard, Administrator")]
(int id, IMovieService service) => Get(id, service));

app.MapGet("/list",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Standard, Administrator")]
(IMovieService service) => List(service));

app.MapPut("/update",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
(Movie movie, IMovieService service) => Update(movie, service));

app.MapDelete("/delete",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
(int id, IMovieService service) => Delete(id, service));

//Methods
IResult Login(UserLogin user, IUserService service)
{
    if(!string.IsNullOrEmpty(user.UserName) &&
        !string.IsNullOrEmpty(user.Password))
    {
        var loggerInUser = service.Get(user);
        if (loggerInUser is null) return Results.NotFound("User not found");
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, loggerInUser.Username),
            new Claim(ClaimTypes.Email, loggerInUser.EmailAddress),
            new Claim(ClaimTypes.GivenName, loggerInUser.GivenName),
            new Claim(ClaimTypes.Surname, loggerInUser.Surname),
            new Claim(ClaimTypes.Role, loggerInUser.Role)
        };

        var token = new JwtSecurityToken (
            issuer: builder.Configuration["Jwt:Issuer"],
            audience: builder.Configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddDays(60),
            notBefore: DateTime.UtcNow,
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
                SecurityAlgorithms.HmacSha256)
            );
        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return Results.Ok(tokenString);
    }

    return Results.BadRequest("Username and password is required");
}


IResult Create(Movie movie, IMovieService movieService)
{
    var result = movieService.Create(movie);
    return Results.Ok(result);
}

IResult Get(int id, IMovieService movieService)
{
    var result = movieService.Get(id);
    if (result is null) return Results.NotFound("Movie not found");

    return Results.Ok(result);
}

IResult List(IMovieService movieService)
{
    var result = movieService.List();
    return Results.Ok(result);
}

IResult Update(Movie movie, IMovieService movieService)
{
    var result = movieService.Update(movie);
    if(result is null) return Results.NotFound("Movie not found");

    return Results.Ok(result);
}

IResult Delete(int id, IMovieService movieService)
{
    var result = movieService.Delete(id);
    if (!result) return Results.BadRequest("Something went wrong");

    return Results.Ok(result);
}

app.UseSwaggerUI();
app.Run();

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Claims;
using System.Text;
using AuthService;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"];
if (string.IsNullOrEmpty(secretKey))
{
    throw new Exception("JWT Key is missing in configuration!");
}
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
int duration = int.Parse(jwtSettings["Duration"] ?? "24");

var app = builder.Build();

if (args.Contains("migrate"))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    Console.WriteLine("Running database migrations...");
    await db.Database.MigrateAsync();
    Console.WriteLine("Migration completed.");
    return;
}

app.MapPost("/auth/login", async (LoginRequest login, UserManager<IdentityUser> userManager) =>
{
    var user = await userManager.FindByEmailAsync(login.Email);
    if (user == null || !await userManager.CheckPasswordAsync(user, login.Password))
        return Results.Unauthorized();

    var handler = new JsonWebTokenHandler();

    var roles = await userManager.GetRolesAsync(user);
    var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };
    foreach (var role in roles) claims.Add(new Claim("role", role));
    
    var token = handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "AuthService",
        Audience = "AllServices",
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(duration),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
    });

    return Results.Ok(new { accessToken = token });
});

app.Run();

public record LoginRequest(string Email, string Password);
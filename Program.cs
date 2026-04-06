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
var secretKey = jwtSettings["Key"];

if (string.IsNullOrEmpty(secretKey))
{
    throw new Exception("JWT Key is missing in configuration!");
}

var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

builder.Services.AddAuthentication()
.AddJwtBearer(options =>
{
    options.MapInboundClaims = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidateIssuer = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidateAudience = true,
        ValidAudience = jwtSettings["Audience"],
        ClockSkew = TimeSpan.Zero,
        RoleClaimType = "role",
        NameClaimType = "sub"
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

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
        Issuer = jwtSettings["Issuer"],
        Audience = jwtSettings["Audience"],
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(24),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
    });

    return Results.Ok(new { accessToken = token });
});

app.UseAuthentication();
app.UseAuthorization();

app.Run();

public record LoginRequest(string Email, string Password);
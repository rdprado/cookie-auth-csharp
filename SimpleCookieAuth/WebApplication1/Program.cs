using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

// ---------------------------------------------------------------
// 1 - Configure the web server with cookie authentication
// ---------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.HttpOnly = true;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// ---------------------------------------------------------------
// 2 - Define in-memory users for demo/testing purposes
// ---------------------------------------------------------------

// In memory users simulating database
var users = new Dictionary<string, string>
{
    ["admin"] = "a123",
    ["tester"] = "t123"
};

// ---------------------------------------------------------------
// 3 - Define application endpoints (routes)
// ---------------------------------------------------------------

// Redirect '/' to secure page if authenticated, or login page otherwise
app.MapGet("/", context =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        context.Response.Redirect("/secure.html");
    }
    else
    {
        context.Response.Redirect("/login.html");
    }

    return Task.CompletedTask;
});

// * GET * /login: Shortcut for human-friendly typing — redirects to /login.html
app.MapGet("/login", context =>
{
    context.Response.Redirect("/login.html");
    return Task.CompletedTask;
});

// * GET * /login.html: Main login page (redirects to /secure.html if already logged in)

app.MapGet("/login.html", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect("/secure.html");
    }

    return Results.File("login.html", "text/html");
});

// * POST * /login: Handles login form submission, validates credentials, issues auth cookie
app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = form["username"];
    var password = form["password"];

    if (!users.TryGetValue(username!, out var storedPassword) || storedPassword != password)
        return Results.BadRequest("Usuário ou senha inválidos.");

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, username!)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    return Results.Redirect("/");
}).AllowAnonymous();

// POST /logout: Clears the authentication cookie and redirects to login
app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    context.Response.Redirect("/login.html");
});

// ---------------------------------------------------------------
// 4 - Enable static file serving (e.g., .html and .css files in wwwroot/)
// ---------------------------------------------------------------

app.UseStaticFiles();

// ---------------------------------------------------------------
// 5 - Protect access to /secure.html by requiring authentication
// ---------------------------------------------------------------

app.Use(async (context, next) =>
{
    if (context.Request.Path == "/secure.html" && !context.User.Identity?.IsAuthenticated == true)
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Unauthorized: Please login first.");
        return;
    }

    await next();
});

// ---------------------------------------------------------------
// 6 - Start the server
// ---------------------------------------------------------------

app.Run();


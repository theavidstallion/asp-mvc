using Auth.Data;
using Auth.Middleware;
using Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting; // Required for environment variable access
using Serilog;
using Serilog.Sinks.MSSqlServer;
using System;
using System.IO;
using System.Reflection;
using Microsoft.AspNetCore.Authentication;

// --- STEP 1: CONFIGURE AND INITIALIZE SERILOG (Pre-Builder Setup) ---

// Manually build configuration to ensure secrets are loaded early.
var configuration = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    // Add environment-specific settings
    .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development"}.json", optional: true)
    .AddEnvironmentVariables()
    // CRITICAL: Manually load User Secrets for security (this finds the connection string)
    .AddUserSecrets(Assembly.GetExecutingAssembly(), optional: true, reloadOnChange: true)
    .Build();

// Retrieve the connection string from the fully built configuration object
var connectionString = configuration.GetConnectionString("DefaultConnection");

try
{
    // Configure Serilog Logger
    Log.Logger = new LoggerConfiguration()
        .ReadFrom.Configuration(configuration)
        .Enrich.FromLogContext()
        .WriteTo.Console()
        .WriteTo.Debug()
        .WriteTo.MSSqlServer(             // Configure Database Sink
                                          // ✅ FIX: Use the retrieved connectionString variable for the sink
            connectionString: connectionString,
            restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Information,
            sinkOptions: new MSSqlServerSinkOptions
            {
                TableName = "AppLogs",
                AutoCreateSqlTable = true
            })
        .CreateLogger();

    Log.Information("Starting web host build.");

    var builder = WebApplication.CreateBuilder(args);

    // CRITICAL FIX: Clear existing configuration sources and use the one we manually built.
    // This ensures that all services (including Serilog and Identity) use the configuration 
    // object that successfully loaded your secrets.json.
    builder.Configuration.AddConfiguration(configuration);

    // 2. Link Serilog to the hosting environment
    builder.Host.UseSerilog();

    // --- STEP 2: REGISTER SERVICES (The Core Logic) ---

    // Register custom DbContext
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        // ✅ FIX: Use the retrieved connectionString variable for EF Core
        options.UseSqlServer(connectionString ?? throw new InvalidOperationException("DefaultConnection string is missing.")));

    // 3. Configure Identity (Users, Roles, and Stores)
    builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.SignIn.RequireConfirmedAccount = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

    // 4. Configure Authentication Middleware and External Providers
    var authenticationBuilder = builder.Services.AddAuthentication();

    authenticationBuilder
        .AddGoogle(options =>
        {
            options.ClientId = builder.Configuration["Google:ClientId"] ?? throw new InvalidOperationException("Google ClientId not found.");
            options.ClientSecret = builder.Configuration["Google:ClientSecret"] ?? throw new InvalidOperationException("Google ClientSecret not found.");
            options.Scope.Add("profile");
            options.ClaimActions.MapJsonKey("picture", "picture", "url");
        })
        .AddFacebook(options =>
        {
            options.AppId = builder.Configuration["Facebook:AppId"];
            options.AppSecret = builder.Configuration["Facebook:AppSecret"];
            options.Scope.Add("email");
            options.Fields.Add("name");
            options.Fields.Add("first_name");
            options.Fields.Add("last_name");
            options.Fields.Add("picture");
            // *** Add the Events handler ***
            options.Events = new Microsoft.AspNetCore.Authentication.OAuth.OAuthEvents
            {
                OnCreatingTicket = context =>
                {
                    // Facebook returns the picture as a complex JSON object:
                    // { "picture": { "data": { "url": "..." } } }

                    // Get the raw JSON response from the external provider
                    var pictureJson = context.User.GetProperty("picture");

                    // Navigate to the "url" property
                    if (pictureJson.TryGetProperty("data", out var data) &&
                        data.TryGetProperty("url", out var url))
                    {
                        string pictureUrl = url.GetString();

                        if (!string.IsNullOrEmpty(pictureUrl))
                        {
                            // *** 3. Manually add the claim using a distinct name ***
                            context.Identity.AddClaim(new System.Security.Claims.Claim("FacebookPicture", pictureUrl));
                        }
                    }

                    return Task.CompletedTask;
                }
            };
        });

    // 5. Configure Identity Cookie Paths (Access Denied / Login)
    builder.Services.ConfigureApplicationCookie(options =>
    {
        options.AccessDeniedPath = "/Auth/AccessDenied";
        options.LoginPath = "/Auth/Login";
    });

    // 6. Register other services
    builder.Services.AddControllersWithViews();
    builder.Services.AddTransient<EmailSender>(); // Your custom email service


    // --- STEP 3: BUILD APP AND CONFIGURE PIPELINE ---

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Home/Error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();

    app.UseStaticFiles();

    app.UseRouting();

    // Custom Middleware
    app.UseRequestLogging();

    // Authentication and Authorization MUST run before MapControllerRoute
    app.UseAuthentication();
    app.UseAuthorization();

    // Execute Data Seeder (Role Builder) - Runs only on startup
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

        await DataSeeder.InitializeAsync(userManager, roleManager);
    }

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");


    app.Run();
}
catch (Exception ex)
{
    // Log fatal error that occurred before the host started
    Log.Fatal(ex, "Application terminated unexpectedly during startup.");
}
finally
{
    // Ensure all buffered logs are written out when the application closes.
    Log.CloseAndFlush();
}
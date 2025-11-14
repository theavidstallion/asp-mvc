using Auth.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Auth.Models;
using Serilog; 
using Serilog.Sinks.MSSqlServer; // Necessary for database sinking
using System.Reflection;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using Auth.Middleware;

// --- STEP 1: CONFIGURE AND INITIALIZE SERILOG (Before Builder) ---
// This enables logging for application startup itself.

var configuration = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json")
    .Build();

var connectionString = configuration.GetConnectionString("DefaultConnection");

try
{
    // Configure Serilog Logger
    Log.Logger = new LoggerConfiguration()
        .ReadFrom.Configuration(configuration) // Reads LogLevel from appsettings.json
        .Enrich.FromLogContext()              // Adds useful context to log entries
        .WriteTo.Console()
        .WriteTo.Debug()
        .WriteTo.MSSqlServer(                 // Configure Database Sink
            connectionString: connectionString,
            restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Information,
            sinkOptions: new MSSqlServerSinkOptions {
                TableName = "AppLogs",             // Table name for logs
                AutoCreateSqlTable = true
            })
        .CreateLogger();

    Log.Information("Starting web host build.");
    var builder = WebApplication.CreateBuilder(args);

    // 2. Link Serilog to the hosting environment
    builder.Host.UseSerilog();

    // --- STEP 2: REGISTER SERVICES (The Core Logic) ---

    // Register custom DbContext
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(connectionString));

    // 3. Configure Identity (Users, Roles, and Stores)
    builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.SignIn.RequireConfirmedAccount = true;
        // ... (Other password/user options go here) ...
    })
    .AddEntityFrameworkStores<ApplicationDbContext>() // Links Identity to the database context
    .AddDefaultTokenProviders();

    // 4. Configure Authentication Middleware and External Providers
    var authenticationBuilder = builder.Services.AddAuthentication();

    authenticationBuilder
        .AddGoogle(options =>
        {
            options.ClientId = builder.Configuration["Google:ClientId"] ?? throw new InvalidOperationException("Google ClientId not found.");
            options.ClientSecret = builder.Configuration["Google:ClientSecret"] ?? throw new InvalidOperationException("Google ClientSecret not found.");
            options.Scope.Add("profile");
        })
        .AddFacebook(options =>
        {
            options.AppId = builder.Configuration["Facebook:AppId"];
            options.AppSecret = builder.Configuration["Facebook:AppSecret"];
            options.Scope.Add("email");
            options.Fields.Add("name");
            options.Fields.Add("first_name");
            options.Fields.Add("last_name");
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
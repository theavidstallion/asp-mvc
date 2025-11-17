// --------------------------------------------
// --------------------------------------------
// --------------------------------------------
// A stupid new class to make sure that EF Core
// can read the DB connection string from secrets.json
// It became necessary after we implemented user
// secrets. 
// I NEED TO DIG DEEPER INTO THIS DAMN THING.
// This is needed at Design Time. 
// --------------------------------------------
// --------------------------------------------
// --------------------------------------------

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System.IO;
using System.Reflection;
using System;
using Microsoft.Extensions.Hosting; // Required for Host

namespace Auth.Data
{
    public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            // 1. Determine the path to configuration files
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development";
            var builder = new ConfigurationBuilder()
                .SetBasePath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!)
                .AddJsonFile("appsettings.json", optional: false)
                .AddJsonFile($"appsettings.{environment}.json", optional: true)
                .AddEnvironmentVariables();

            // ✅ CRITICAL FIX: Manually load user secrets into the configuration builder
            // Get the assembly where your UserSecretsId is defined (typically the executing assembly)
            var assembly = Assembly.GetExecutingAssembly();
            builder.AddUserSecrets(assembly, optional: true);

            IConfigurationRoot configuration = builder.Build();

            // 2. Retrieve the connection string (will now pull from secrets.json)
            var connectionString = configuration.GetConnectionString("DefaultConnection");

            if (string.IsNullOrEmpty(connectionString))
            {
                throw new InvalidOperationException(
                    "Connection string 'DefaultConnection' not found. " +
                    "Ensure it is set in appsettings.json or user secrets.");
            }

            // 3. Build context options
            var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
            optionsBuilder.UseSqlServer(connectionString);

            return new ApplicationDbContext(optionsBuilder.Options);
        }
    }
}
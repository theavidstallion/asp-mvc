using Auth.Models;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Auth.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]

        [HttpGet]
        public IActionResult Error()
        {
            var exceptionHandlerPathFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();

            // You can log the error here if you haven't already caught it upstream
            _logger.LogError(exceptionHandlerPathFeature?.Error, "Unhandled exception occurred.");

            return View();
        }

        [HttpGet]
        public IActionResult TriggerError()
        {
            try
            {
                // Simulate a recoverable failure (e.g., a connection attempt failed)
                throw new InvalidOperationException("Simulated minor network failure during processing.");
            }
            catch (Exception ex)
            {
                // 1. Log the failure at the ERROR level
                _logger.LogError(ex, "Failed to complete background task for testing.");

                // 2. CRITICAL STEP: Throw a *new* or the *original* exception 
                //    to break the method and trigger the global error handler.
                throw;

                // Note: If you used 'throw new Exception("Fatal crash");' that also works.
            }
            return View(); // This line is unreachable due to 'throw;'
        }
    }
}

namespace Auth.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;
        
        // Constructor
        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        
        // Invoke method
        public async Task InvokeAsync (HttpContext context)
        {
            _logger.LogInformation("Handling request: {Method} {Url}", context.Request.Method, context.Request.Path);
            
            await _next(context);
        }
    }


    // Extension class and method to add the middleware to the pipeline
    public static class RequestLoggingMiddlewareExtensions
    {
        public static IApplicationBuilder UseRequestLogging(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<RequestLoggingMiddleware>();
        }
    }
}

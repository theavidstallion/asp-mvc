using System;

namespace Auth.Models
{
    // This is a plain model used only for reading data from the Serilog table
    public class AppLogs
    {
        public int Id { get; set; }

        // Use DateTimeOffset because Serilog stores time zone information
        public DateTime TimeStamp { get; set; }

        // Level is always present and small, but store as string
        public string Level { get; set; }

        // Message is the user-friendly output
        public string? Message { get; set; }

        // Exception is the full stack trace
        public string? Exception { get; set; }

        // Properties contains structured data (JSON/XML)
        public string? Properties { get; set; }
    }
}
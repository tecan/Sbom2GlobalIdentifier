using System;

namespace Tecan.Tools.Sbom2GlobalIdentifier.Exceptions
{
    /// <summary>
    /// Constructs a custom exception with the specified detail message.
    /// </summary>
    /// <param name="message">The message that describes the error</param>
    public class InvalidPurlException : Exception
    {
        public InvalidPurlException( string message )
            : base( message )
        { }

        public InvalidPurlException( string message, Exception innerException )
            : base( message, innerException )
        { }
    }
}

using System;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    internal static class ConsoleOutput
    {
        /// <summary>
        /// if the <paramref name="color"/> is set, use this color to write to console else default to white
        /// </summary>
        /// <param name="text"> Text to write to the console </param>
        /// <param name="color"> Color of the text </param>
        public static void WriteToConsole( string text, ConsoleColor color = ConsoleColor.White )
        {
            var originalConsoleColor = Console.ForegroundColor;

            Console.ForegroundColor = color;
            Console.WriteLine( text );
            Console.ForegroundColor = originalConsoleColor;
        }

    }
}

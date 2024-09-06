using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    public partial class FileManipulator
    {
        /// <summary>
        /// lazy string that represents the projectName for the results file that is created to log the results
        /// </summary>
        private Lazy<string> _resultFileName;

        /// <summary>
        /// lazy string that represents the directory for the <see cref="_resultFileName"/>
        /// </summary>
        private Lazy<string> _resultsFileDirectory;

        /// <summary>
        /// is used exclusively to group the findings for logging purposes.
        /// </summary>
        private static readonly Dictionary<string, List<string>> LoggingContainer = [];

        /// <summary>
        /// if <see cref="_resultFileName"/> been initilized, use the params to lazily initialize it
        /// </summary>
        /// <param name="projectName"> the name of the project extracted from the provided file </param>
        public void UpdateResultsFileName( string projectName )
        {
            var dateTime = $"{DateTime.Now:yyyy_MM_dd_HH_mm}";
            var sanitizedProjectName = UncommonPatternForFileName().Replace( projectName ?? "", "_" );

            _resultFileName = new Lazy<string>( () => string.Concat( $"Result__{dateTime}_",
                                                      string.IsNullOrEmpty( sanitizedProjectName ) ? "UnknownProjectName" : sanitizedProjectName,
                                                      ".txt" ) );
        }

        /// <summary>
        /// return the <see cref="_logFileDir.Value"/> if it has been initialized, else return an exception
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public string LogDirPath => _resultsFileDirectory == null
            ? throw new InvalidOperationException( "LogFileDir has not been initialized, hence cannot be accessed" )
            : _resultsFileDirectory.Value;

        /// <summary>
        /// generic setter for the <see cref="_resultsFileDirectory"/>. once set, it cant be updated and the user will also be notified
        /// </summary>
        /// <param projectName="valueFactory"></param>
        public void InitializeResultsFileDirectory( Func<string> valueFactory )
        {
            if( string.IsNullOrEmpty( _resultsFileDirectory?.Value ) )
            {
                _resultsFileDirectory = new Lazy<string>( valueFactory );
                return;
            }
            ConsoleOutput.WriteToConsole( $"INFO: LogFileDir has already been initialized with {_resultsFileDirectory.Value} and will not be updated" );

        }

        /// <summary> 
        /// Takes all the information that we have from <see cref="LoggingContainer"/> and writes it to a directory specified by <see cref="_resultsFileDirectory"/> 
        /// in a human understandable way.
        /// If the <see cref="_resultFileName"/> is null, then it sets a default projectName for it using <see cref="DateTime.Now"/> and then creates the final filePath
        /// </summary>
        public void WriteToResultFile()
        {
            var sortedDict = LoggingContainer.OrderBy( kvp => kvp.Key )
                             .ToDictionary( kvp => kvp.Key, kvp => kvp.Value.OrderByDescending( v => v, StringComparer.InvariantCultureIgnoreCase ).ToList() );

            var fileName = _resultFileName != null ? _resultFileName.Value : $"{DateTime.Now:yyyy_MM_dd_HH_mm}__Sbom2GlobalIdentifier.txt";

            var filePath = Path.Combine( _resultsFileDirectory?.Value, fileName );

            using var writer = new StreamWriter( filePath, append: false );
            writer.WriteLine( $"------------------------------------------------  {DateTime.Now}  ------------------------------------------------" );
            writer.WriteLine( " " );
            foreach( var kvp in sortedDict ) //string, List<string>
            {
                foreach( var value in kvp.Value ) // foreach string in List<string>
                {
                    writer.WriteLine( value );
                }
                writer.WriteLine( "" );
            }
            ConsoleOutput.WriteToConsole( $"\nGenerated Log File {filePath}", ConsoleColor.Yellow );
            ConsoleOutput.WriteToConsole( Constants.EXECUTION_COMPLETE );
        }

        /// <summary>
        /// add the message to the corresponding key in the Dictionary
        /// </summary>
        /// <param projectName="key"></param>
        /// <param projectName="message"></param>
        public static void AddToContainer( string key, string message )
        {
            if( !LoggingContainer.TryGetValue( key, out var value ) )
            {
                value = [];
                LoggingContainer[key] = value;
            }

            value.Add( message );
        }

        /// <summary>
        /// denotes all the characters that are uncanny for a file projectName
        /// </summary>
        /// <returns></returns>
        [GeneratedRegex( @"[^A-Za-z0-9\-_.]" )]
        internal static partial Regex UncommonPatternForFileName();
    }
}


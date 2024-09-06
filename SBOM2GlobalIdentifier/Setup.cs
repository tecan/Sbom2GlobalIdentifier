using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommandLine;
using static Tecan.Tools.Sbom2GlobalIdentifier.ConsoleOutput;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    public sealed class Setup
    {
        /// <summary>
        /// constructor for <see cref="Setup"/>. Allows more flexibility as to which instance of each attribute is to be set for an instance of <see cref="Setup"/>
        /// </summary>
        /// <param name="explorers"></param>
        public Setup( IEnumerable<IExplorer> explorers, FileManipulator fileManipulator, InformationExtractor infoExtractor )
        {
            _explorers = explorers;
            _fileManipulator = fileManipulator;
            _informationExtractor = infoExtractor;
        }

        /// <summary>
        /// enumerable type of the explorers used for this class.
        /// </summary>
        private readonly IEnumerable<IExplorer> _explorers;

        /// <summary>
        /// instance of <see cref="FileManipulator"/> mainly used for the adding and manipulating the results file at the end of the execution
        /// </summary>
        private readonly FileManipulator _fileManipulator;

        /// <summary>
        /// instance of <see cref="InformationExtractor"/> which is used mainly to extract the info from the provided input file
        /// </summary>
        private readonly InformationExtractor _informationExtractor;

        /// <summary>
        /// represents the CWD for the Application and can be reinitialized in <see cref="ParseConfigurationOptions(ConfigurationOptions)"/>
        /// </summary>
        public string CurrentActiveDirectory { get; private set; } = Directory.GetCurrentDirectory();

        /// <summary>
        /// denotes the max retry Count for all the APIs used. When max count is speicified using --maxRetryCount, then it uses the value specified else defaults to the
        /// default value defined in <see cref="ConfigurationOptions.MaxRetryCount"/>.
        /// -1 is just a placeholder
        /// </summary>
        private int _maxRetryCountForAllApis = -1;

        /// <summary>
        /// entry Point for the application
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public async Task RunAsync( string[] args )
        {
            try
            {
                _ = Parser.Default.ParseArguments<ConfigurationOptions>( args )
                    .WithParsed( options => ParseConfigurationOptions( options ) )
                    .WithNotParsed( HandleInvalidConfigurationOptions );

                // search only for valid JSON validFiles in the CWD of the tool
                var validFiles = GetValidJsonFiles( CurrentActiveDirectory );

                if( !validFiles.Any() )
                {
                    _ = await RequestAndProcessFilesAsync( new UserInputService() );
                }
                else
                {
                    await ValidateAndProcessFilesAsync( validFiles );
                }
            }
            catch( ArgumentException ex )
            {
                WriteToConsole( ex.Message, ConsoleColor.Red );
            }
            catch( Exception ex ) when( ex.InnerException != null )
            {
                WriteToConsole( $"{Constants.GENERAL_ERROR} {ex.Message}", ConsoleColor.Red );
            }
            finally
            {
                _fileManipulator.WriteToResultFile();
            }
        }

        /// <summary>
        /// return the maxRetryCount if it has been properly initialized
        /// </summary>
        public int MaxRetryCount => _maxRetryCountForAllApis == -1
            ? throw new InvalidOperationException( $"FATAL: MaxRetryCountBeforeSkip has not been correctly initialized yet, cannot access to it before correct initialization" )
            : _maxRetryCountForAllApis;


        public void InitializeMaxRetryCountBeforeSkip( string maxRetryCount )
        {
            if( _maxRetryCountForAllApis > 0 )
            {
                ConsoleOutput.WriteToConsole( $"INFO: MaxRetryCountBeforeSkip has already been initialized with {_maxRetryCountForAllApis} and will not be updated" );
            }
            else
            {
                _maxRetryCountForAllApis = int.TryParse( maxRetryCount, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedValue )
                    && parsedValue > 0
                    ? parsedValue
                    : -1 * parsedValue;  // just convert it to a positive integer and proceed since it would just be overkill to throw a runtime exception

                InitializeRetryCountInExplorers();
            }
        }

        /// <summary>
        /// after the <see cref="_maxRetryCountForAllApis"/> has been set, use this count for all the explorers present in <see cref="_explorers"/>
        /// </summary>
        private void InitializeRetryCountInExplorers()
        {
            foreach( var explorer in _explorers )
            {
                if( explorer is CpeExplorer cpeExplorer )
                {
                    cpeExplorer.MaxRetryCount = _maxRetryCountForAllApis;
                }
                if( explorer is PurlExplorer purlExplorer )
                {
                    purlExplorer.MaxRetryCount = _maxRetryCountForAllApis;
                }
            }
        }

        /// <summary>
        /// parse all the arguments from the CLP to better integrate it into the current functionality
        /// </summary>
        /// <param name="opts"></param>
        public void ParseConfigurationOptions( ConfigurationOptions opts )
        {
            // included as per request on the NVD website
            WriteToConsole( Constants.NVD_NOTICE );

            //apiKey
            CheckAndSetApiKey( opts?.ApiKey );

            //dirPath
            if( !string.IsNullOrEmpty( opts?.DirPath ) )
            {
                CurrentActiveDirectory = opts.DirPath.Trim();
            }
            WriteToConsole( $"INFO: Initialized Dir Path to {CurrentActiveDirectory}" );

            //stringToAvoid
            if( !string.IsNullOrEmpty( opts?.StringToAvoid ) )
            {
                _informationExtractor.InitializeStringToAvoid( () => opts.StringToAvoid.ToLowerInvariant() );
            }

            //resultsFileDirectory
            //if the user has provided a logFileDir explicitly, then use it, else initialize the logFileDir with the CWD
            if( !string.IsNullOrEmpty( opts?.ResultDirPath ) )
            {
               _fileManipulator.InitializeResultsFileDirectory( () => opts.ResultDirPath.ToLowerInvariant() );
            }
            else
            {
                _fileManipulator.InitializeResultsFileDirectory( () => CurrentActiveDirectory.ToLowerInvariant() );
            }
            WriteToConsole( $"INFO: Initialized Log File Directory to {_fileManipulator.LogDirPath}" );

            //maxRetryCount
            if( !string.IsNullOrEmpty( opts.MaxRetryCount ) )
            {
                InitializeMaxRetryCountBeforeSkip( opts.MaxRetryCount );
            }
            WriteToConsole( $"INFO: Initialized max Retry Count for a component to {MaxRetryCount}" );
        }

        public static void HandleInvalidConfigurationOptions( IEnumerable<Error> errs )
        {
            var containsHelp = errs.Any( error =>
                            error is HelpRequestedError ||
                            error.Tag == ErrorType.HelpRequestedError
                        );

            if( !containsHelp )
            {
                throw new ArgumentException( Constants.FAULTY_OPTIONS_PROVIDED );
            }
        }

        public void CheckAndSetApiKey( string arg )
        {
            foreach( var explorer in _explorers )
            {
                if( explorer is CpeExplorer cpeExplorer )
                {
                    if( !string.IsNullOrEmpty( arg ) )
                    {
                        cpeExplorer.ApiKey = arg;
                        WriteToConsole( $"{Constants.API_KEY_PRESENT}", ConsoleColor.Green );
                    }
                    else if( File.Exists( Constants.SECRETS_FILE ) && !string.IsNullOrEmpty( Constants.SECRETS_FILE ) )
                    {
                        cpeExplorer.ApiKey = File.ReadAllText( Constants.SECRETS_FILE );
                        WriteToConsole( $"{Constants.API_KEY_PRESENT}", ConsoleColor.Green );
                    }
                    else
                    {
                        WriteToConsole( $"{Constants.NO_API_KEY}", ConsoleColor.DarkYellow );
                    }
                }
            }
        }

        /// <summary>
        /// exclusively add only the JSON validFiles that start with 'bom'
        /// </summary>
        /// <param name="currentDirectory"></param>
        /// <returns></returns>
        public static IEnumerable<FileInformation> GetValidJsonFiles( string currentDirectory )
        {
            var validFiles = new List<FileInformation>();
            var allFiles = Directory.GetFiles( currentDirectory );
            foreach( var currentFileName in allFiles )
            {
                var name = Path.GetFileName( currentFileName );
                if( name.StartsWith( "bom", StringComparison.InvariantCultureIgnoreCase ) &&
                    Path.GetExtension( currentFileName ).Equals( ".json", StringComparison.InvariantCultureIgnoreCase ) )
                {
                    validFiles.Add( new( currentFileName, "JSON" ) );
                }
            }
            return validFiles;
        }

        /// <summary>
        /// if the <see cref="CurrentActiveDirectory"/> does not have any valid validFiles, ask the user for a input file
        /// if the user provided a json file, then use it to extract the relevant information 
        /// </summary>
        /// <returns></returns>
        public async Task<bool> RequestAndProcessFilesAsync( IUserInputService userInputService )
        {
            WriteToConsole( $"{Constants.NO_FILE_FOUND} {CurrentActiveDirectory}" );
            var componentNames = new List<string>();

            while( true )
            {
                WriteToConsole( $"\n{Constants.INPUT_FULL_PATH_TO_FILE}" );
                var filePath = userInputService?.ReadLine();

                if( !string.IsNullOrWhiteSpace( filePath ) && IsJsonFile( filePath ) )
                {
                    await ProcessFileAsync( filePath, componentNames );
                    InitializeResultsFileName( componentNames );
                    return true;
                }
                else
                {
                    // ask the user again
                }
            }        
        }

        private static bool IsJsonFile( string filePath )
        {
            if( !string.IsNullOrWhiteSpace( filePath ) )
            {
                if( filePath.ToLowerInvariant().EndsWith( ".json", StringComparison.InvariantCultureIgnoreCase ) )
                {
                    return true;
                }
                else
                {
                    WriteToConsole( Constants.FILE_FORMAT_NOT_SUPPORTED );
                    return false;
                }
            }
            return false;
        }

        /// <summary>
        /// if valid validFiles were found in <see cref="CurrentActiveDirectory"/>, use the found file to send the req to the API
        /// </summary>
        /// <param name="validFiles"></param>
        /// <returns></returns>
        public async Task ValidateAndProcessFilesAsync( IEnumerable<FileInformation> validFiles )
        {
            if( !validFiles.Any() )
            {
                WriteToConsole( $"{Constants.NO_ASSEMBLY_INFO_PRESENT}", ConsoleColor.Red );
                return;
            }

            string bomJsonFilePath;
            string fileName;

            var componentNames = new List<string>();
            foreach( var fileInfo in validFiles )
            {
                if( !string.IsNullOrEmpty( fileInfo.FileName ) && !string.IsNullOrEmpty( fileInfo.FileType ) )
                {
                    fileName = Path.GetFileName( fileInfo.FileName );
                    WriteToConsole( $"Using {CurrentActiveDirectory}\\{fileName}" );

                    if( string.Equals( fileInfo.FileType.ToLowerInvariant(), "json", StringComparison.InvariantCultureIgnoreCase ) )
                    {
                        bomJsonFilePath = fileInfo.FileName.ToLowerInvariant();
                        await ProcessFileAsync( bomJsonFilePath, componentNames );
                    }
                    else
                    {
                        //pass
                    }
                }
            }
            InitializeResultsFileName( componentNames );       
        }

        private void InitializeResultsFileName(IList<string> componentNames)
        {
            var logFileName = string.Empty;
            foreach( var componentName in componentNames )
            {
                logFileName = string.Concat( logFileName, componentName );
                logFileName = string.Concat( logFileName, "__" );
            }

            _fileManipulator.UpdateResultsFileName( logFileName );
        }

        /// <summary>
        /// this function has 2 main tasks, one is PURL generation for all the entries in the SBOM file provided, another is CPE lookups at NVD
        /// </summary>
        /// <param name="bomJsonFilePath"></param>
        /// <returns></returns>
        private async Task ProcessFileAsync( string bomJsonFilePath, IList<string> componentNames )
        {
            var extractor = new InformationExtractor();
            var recordList = extractor.ExtractInfo( bomJsonFilePath, componentNames );

            if( recordList.Count == 0 )
            {
                WriteToConsole( $"\n{Constants.NO_ASSEMBLY_INFO_PRESENT}" );
                return;
            }

            foreach( var explorer in _explorers )
            {
                await explorer.ExploreAsync( recordList );
            }
        }

        /// <summary>
        /// display a progress Bar like structure for the end user to see what the current progress is
        /// </summary>
        /// <param name="totalTasks"></param>
        /// <param name="currentTask"></param>
        internal static void UpdateProgressBar( int totalTasks, int currentTask )
        {
            const int hundred = 100;
            var progress = (int)( (double)currentTask / totalTasks * hundred );
            var bar = "[" + new string( '#', progress / 2 ) + new string( '.', ( hundred - progress ) / 2 ) + "]";
            const int lowerRange = 79;
            const int midRange = 96;

            if( progress <= lowerRange )
            {
                WriteToConsole( $"{bar} {progress}%" );
            }
            else if( progress is > lowerRange and < midRange )
            {
                WriteToConsole( $"{bar} {progress}%", ConsoleColor.Green );
            }
            else if( progress is > midRange and <= hundred )
            {
                WriteToConsole( $"{bar} {progress}%", ConsoleColor.DarkGreen );
            }
            else
            {
                //pass
            }
        }
    }
}

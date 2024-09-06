using System.Collections.ObjectModel;
using CommandLine;
using Moq;

namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    internal class SetupTests : TestBase
    {
        [Test]
        public void CheckAndSetApiKey_MissingSecretFile_Null()
        {
            var cpeExplorer = new CpeExplorer();
            var explorerContainer = new Collection<IExplorer>
            {
                 cpeExplorer,
            };
            var setup = new Setup( explorerContainer, null, null );

            setup.CheckAndSetApiKey( string.Empty );

            Assert.IsNull( cpeExplorer.ApiKey, $"Expected ApiKey to be null, but it was {cpeExplorer.ApiKey}" );
        }

        [Test]
        public void CheckAndSetApiKey_ApiKeyExists_Successful()
        {
            var cpeExplorer = new CpeExplorer();
            var explorerContainer = new Collection<IExplorer>
            {
                cpeExplorer,
            };

            var setup = new Setup( explorerContainer, null, null );

            // args provided, doesnt matter if file exists
            setup.CheckAndSetApiKey( DummyVariables.DummyApiKey2 );
            Assert.AreEqual( DummyVariables.DummyApiKey2, cpeExplorer.ApiKey, $"Expected ApiKey to be {DummyVariables.DummyApiKey2}, but was {cpeExplorer.ApiKey} instead" );
        }

        [Test]
        public void CheckAndSetApiKey_SecretFileExists_Successful()
        {
            var cpeExplorer = new CpeExplorer();
            var explorerContainer = new Collection<IExplorer>
            {
                cpeExplorer,
            };
            var setup = new Setup( explorerContainer, null, null );

            //no args provided, but the secrets file exists
            var filePath = Path.Combine( AppPath!, Constants.SECRETS_FILE );
            if( !File.Exists( filePath ) )
            {
                using( var stream = File.Create( filePath ) ) { };
                File.WriteAllText( filePath, DummyVariables.DummyApiKey2 );
            }
            setup.CheckAndSetApiKey( string.Empty );

            Assert.AreEqual( DummyVariables.DummyApiKey2, cpeExplorer.ApiKey, $"Expected ApiKey to be {DummyVariables.DummyApiKey2}, but was {cpeExplorer.ApiKey} instead" );
            File.Delete( filePath );
        }

        [Test]
        public void CheckAndSetApiKeySuccessful_SecretFileAndArgsExists()
        {
            var cpeExplorer = new CpeExplorer();
            var explorerContainer = new Collection<IExplorer>
            {
                 cpeExplorer,
            };
            var setup = new Setup( explorerContainer, null, null );

            //no args provided, but the secrets file exists
            var filePath = Path.Combine( AppPath!, Constants.SECRETS_FILE );
            if( !File.Exists( filePath ) )
            {
                using( var stream = File.Create( filePath ) ) { };
                File.WriteAllText( filePath, DummyVariables.DummyApiKey2 );
            }
            setup.CheckAndSetApiKey( DummyVariables.DummyApiKey1 );
            Assert.AreEqual( DummyVariables.DummyApiKey1, cpeExplorer.ApiKey, $"Expected ApiKey to be {DummyVariables.DummyApiKey1}, but was {cpeExplorer.ApiKey} instead" );
            File.Delete( filePath );
        }

        [Test]
        public async Task RequestAndProcessFilesAsync_NoFilesProvided_SuccessfulRequest()
        {
            IEnumerable<IExplorer> explorers = new Collection<IExplorer>();
            var fileManipulator = new FileManipulator();
            var informationExtractor = new InformationExtractor();
            var setup = new Setup( explorers, fileManipulator, informationExtractor );

            var mockInputService = new Mock<IUserInputService>();
            _ = mockInputService.SetupSequence( x => x.ReadLine() )
                            .Returns( "invalid_file.txt" )
                            .Returns( Path.Combine( AppPath!, "SampleFiles\\bom - Empty.json" ) );

            using( var consoleOutput = new StringWriter() )
            {
                Console.SetOut( consoleOutput );

                var wasInputFileValid = await setup.RequestAndProcessFilesAsync( mockInputService.Object );

                var output = consoleOutput.ToString();
                Assert.IsTrue( output.Contains( Constants.FILE_FORMAT_NOT_SUPPORTED ) );

                Assert.IsTrue( wasInputFileValid );
            }
            Console.SetOut( new StreamWriter( Console.OpenStandardOutput() ) { AutoFlush = true } );
        }

        [Test]
        public void ArgParse_ValidArgumentsProvided_ParseSuccessfully()
        {
            var dirPath = Path.Combine( AppPath!, "SampleFiles" );
            const string excludeString = "banana";
            const string maxRetryCount = "10";

            var cpeExplorer = new CpeExplorer();
            var explorerContainer = new Collection<IExplorer>
            {
                cpeExplorer

            };
            var fileManipulator = new FileManipulator();
            var informationExtractor = new InformationExtractor();
            var setup = new Setup( explorerContainer, fileManipulator, informationExtractor );

            var args = new[] { "--apiKey", DummyVariables.DummyApiKey1, "--dirPath", dirPath, "--exclude", excludeString, "--maxRetryCount", maxRetryCount };
            _ = Parser.Default.ParseArguments<ConfigurationOptions>( args )
                .WithParsed( opts => setup.ParseConfigurationOptions( opts ) );

            Assert.AreEqual( cpeExplorer.ApiKey, DummyVariables.DummyApiKey1, $"Expected api key to be {DummyVariables.DummyApiKey1} but was {cpeExplorer.ApiKey} instead" );
            Assert.AreEqual( setup.CurrentActiveDirectory, dirPath, $"Expected CAD to be {dirPath} but was {setup.CurrentActiveDirectory} instead" );
            Assert.AreNotEqual( setup.MaxRetryCount, maxRetryCount, $"Expected Setup.MaxRetryCount to not be reinitialized but it was" );
            Assert.AreEqual( informationExtractor.StringToAvoid, excludeString, $"Expected InformationExtractor.StringToAvoid_Initialization_Success to not be reinitialized with {excludeString} but it was." );
        }

        [Test]
        public void ArgParse_InvalidArgsProvided_HandleParseError()
        {
            var args = new[] { "--invalid", "value" };

            var ex = Assert.Throws<ArgumentException>( () =>
                Parser.Default.ParseArguments<ConfigurationOptions>( args )
                    .WithNotParsed( Setup.HandleInvalidConfigurationOptions ) );

            Assert.IsNotNull( ex );
        }

    }
}

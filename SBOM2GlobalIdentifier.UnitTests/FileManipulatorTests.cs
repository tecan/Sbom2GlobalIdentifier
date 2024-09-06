namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    internal class FileManipulatorTests : TestBase
    {      
        [SetUp]
        public void Setup()
        {
            ResetLogEntries();
        }

        [Test]
        public void LogContainer_ValuesProvided_WriteSuccess()
        {
            const string recordName = "sharpziplib";
            const string recordVersion = "1.3.1";
            var logEntries = new[]
            {
                $"Name: {recordName}, Version: {recordVersion}"  ,
                "~ CPE : $CPE with (**** EXACT VERSION MATCH ****) found"   ,
                "cpe:2.3:a:sharpziplib_project:sharpziplib:1.3.1:*:*:*:*:*:*:*"
            };

            foreach( var entry in logEntries )
            {
                FileManipulator.AddToContainer( recordName, entry );
            }

            var defaultFileName = $"{DateTime.Now:yyyy_MM_dd_HH_mm}__Sbom2GlobalIdentifier.txt";
            if( File.Exists( defaultFileName ) )
            {
                File.Delete( defaultFileName );
            }
            var fileManipulator = new FileManipulator();
            fileManipulator.InitializeResultsFileDirectory(()=>AppPath!);
            fileManipulator.WriteToResultFile();

            Assert.IsTrue( File.Exists( defaultFileName ), $"File with default name:{defaultFileName} was not created" );

            var log = File.ReadAllText( defaultFileName );
            var entries = log.Split( '\n' );
            Assert.AreEqual( 7, entries.Length );

        }

        [Test]
        public void LogDirPath_Reinitialization_ReinitializationFailure()
        {
            var newLogDir = DummyVariables.DummyNewDirPath;
            var fileManipulator = new FileManipulator();

            fileManipulator.InitializeResultsFileDirectory( () => newLogDir );

            const string newDirPath = "test";
            fileManipulator.InitializeResultsFileDirectory( () => newDirPath );

            Assert.AreNotEqual( fileManipulator.LogDirPath, newDirPath, $"ResultDirPath should not have been reinitialized, but it was" );
        }
    }
}

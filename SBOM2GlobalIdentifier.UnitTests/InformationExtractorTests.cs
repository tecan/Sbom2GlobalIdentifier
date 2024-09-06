namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    public class InformationExtractorTests : TestBase
    {
        [Test]
        public void GetValidJsonFiles_FolderProvided_ValidFilesSelected()
        {
            var files = Setup.GetValidJsonFiles( Path.Combine( AppPath!, "SampleFiles" ) );
            var expected = new[] { "bom - 1.json", "bom - Minimal.json", "bom - Duplicates.json", "bom - Empty.json", "bom-Invalid.json" };

            Assert.AreEqual( expected.Length, files.Count(), $"{expected.Length} files expected" );

            foreach( var testFile in expected )
            {
                var fullPath = Path.Combine( AppPath!, "SampleFiles", testFile );
                var found = files.FirstOrDefault( f => StringComparer.InvariantCultureIgnoreCase.Equals( fullPath, f.FileName ) );
                Assert.IsNotNull( found, $"File not found: {testFile}" );
            }
        }

        [Test]
        public void StringToAvoid_Initialization_Success()
        {
            var informationExtractor = new InformationExtractor();
            var stringToAvoid = "apple";
            informationExtractor.InitializeStringToAvoid( () => stringToAvoid );

            Assert.AreEqual( informationExtractor.StringToAvoid, stringToAvoid, $"Expected '{stringToAvoid}', got '{informationExtractor.StringToAvoid}' instead" );
        }

        [Test]
        public void ExtractInfo_FileProvided_CorrectEntriesPresent()
        {
            var filePath = Path.Combine( AppPath!, "SampleFiles\\bom - 1.json" );
            var extractor = new InformationExtractor();
            var componentNames = new List<string>();

            const string stringToAvoid = "tecan";
            extractor.InitializeStringToAvoid( () => stringToAvoid );
            var recordList = extractor.ExtractInfo( filePath, componentNames );

            Assert.AreEqual( stringToAvoid, extractor.StringToAvoid, "stringToAvoid has not been initialized with the correct value for the file being tested" );
            Assert.AreEqual( 19, recordList.Count, "19 records expected" );

            var versions = new Dictionary<string, string>( StringComparer.InvariantCultureIgnoreCase )
            {
                 { "asyncio", "0.1.26.0"},
                 { "automapper", "6.2.2"},
                 { "castle.core", "4.4.0"},
                 { "commonservicelocator", "1.3.0"},
                 { "jetbrains.annotations", "11.1.0"},
                 { "linq2db", "2.6.4"},
                 { "linq2db.sqlite", "2.9.1"},
                 { "moq", "4.11.0"},
                 { "ncalc", "1.3.8"},
                 { "netmq", "4.0.0.1" },
                 { "newtonsoft.json", "12.0.3"},
                 { "pdfsharp-migradoc-wpf", "1.50.5147"},
                 { "prism", "4.1.0.0"},
                 { "prism.mefextensions", "4.1.0.0"},
                 { "sharpziplib", "1.3.1"},
                 { "system.collections.immutable", "1.5.0"},
                 { "system.data.sqlite.core", "1.0.109.2"},
                 { "system.threading.tasks.extensions", "4.5.2"},
                 { "system.valuetuple", "4.5.0"},
            };

            foreach( var record in recordList )
            {
                var name = record.AssemblyName;
                Assert.IsTrue( versions.ContainsKey( name ), $"Unexpected assembly: {name}" );
                Assert.AreEqual( versions[name], record.AssemblyVersion, $"Unexpected Version {record.AssemblyVersion}" );
            }
        }

        [Test]
        public void ExtractInfo_EmptyFileProvided_NoEntries()
        {
            var filePath = Path.Combine( AppPath!, "SampleFiles\\bom - Empty.json" );
            var extractor = new InformationExtractor();
            var componentNames = new List<string>();

            var recordList = extractor.ExtractInfo( filePath, componentNames );
            Assert.AreEqual( 0, recordList.Count, "0 entries expected" );
        }

        [Test]
        public void ExtractInfo_InvalidFileProvided_NoEntries()
        {
            var filePath = Path.Combine( AppPath!, "SampleFiles\\bom-invalid.json" );
            var extractor = new InformationExtractor();
            var componentNames = new List<string>();

            var recordList = extractor.ExtractInfo( filePath, componentNames );
            Assert.AreEqual( 0, recordList.Count, "0 entries expected" );
        }

        [Test]
        public void StringToBeAvoided_Reinitialization_ReinitializationFailure()
        {
            var originalStringToAvoid = "avoid";
            var newStringToAvoid = "bananaString";
            var informationExtractor = new InformationExtractor();

            informationExtractor.InitializeStringToAvoid( () => originalStringToAvoid );
            informationExtractor.InitializeStringToAvoid( () => newStringToAvoid );

            Assert.AreNotEqual( informationExtractor.StringToAvoid, newStringToAvoid, $"StringToAvoid_Initialization_Success should not have been reinitialized, but it was" );
        }
    }
}
using System.Collections.ObjectModel;
using Sbom2GlobalIdentifier.UnitTests.Helpers;

namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    internal class FileProcessingTests : TestBase
    {
        [SetUp]
        public void Setup() =>
            ResetLogEntries();

        [Test]
        public async Task ValidateAndProcessFilesAsync_FileProvided_Success()
        {
            var filePath = Path.Combine( AppPath!, "SampleFiles\\bom - Minimal.json" );

            var explorerContainer = new Collection<IExplorer>
            {
                  new CpeExplorer(),
                  new PurlExplorer()
            };
            var fileManipulator = new FileManipulator();
            var informationExtractor = new InformationExtractor();

            var setup = new Setup( explorerContainer, fileManipulator, informationExtractor );

            await setup.ValidateAndProcessFilesAsync( new[] { new FileInformation( filePath, "json" ) } );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 2, logContainers.Count, "2 LogContainers expected" );

            const string assemblyName1 = "asyncio";
            const string assemblyVersion1 = "0.1.26";

            const string assemblyName2 = "microsoft.bcl.asyncinterfaces";
            const string assemblyVersion2 = "1.1.0";

            var expectedAsyncIO = new[] {
                $"Name: {assemblyName1}, Version: {assemblyVersion1}",
                $"~ CPE : No matching CPEs were found for {assemblyName1}",
                "~ PURL: Nearest hit was for version:0.0.2 (NPM)",
                $"~ PURL: pkg:nuget/{assemblyName1}@{assemblyVersion1}"
            };
            var expectedAsyncInterface = new[] {
               $"Name: {assemblyName2}, Version: {assemblyVersion2}",
               $"~ CPE : No matching CPEs were found for {assemblyName2}",
               $"~ PURL: pkg:nuget/{assemblyName2}@{assemblyVersion2}"
            };

            var expected = new Dictionary<string, string[]>()
            {
                { assemblyName1, expectedAsyncIO },
                { assemblyName2, expectedAsyncInterface}
            };

            foreach( var key in logContainers.Keys )
            {
                var messages = logContainers[key];
                var expectedMessages = expected[key];
                ValidateLogOutput( expectedMessages, messages, false );
            }
        }

        [Test]
        public async Task ValidateAndProcessFilesAsync_DuplicatePackagesPresent_SuccessfulProcessing()
        {
            var filePathJson = Path.Combine( AppPath!, "SampleFiles\\bom - Duplicates.json" );

            var explorerContainer = new Collection<IExplorer>
            {
                new CpeExplorer(),
                new PurlExplorer()
            };
            var fileManipulator = new FileManipulator();
            var informationExtractor = new InformationExtractor();

            var setup = new Setup( explorerContainer, fileManipulator, informationExtractor );

            await setup.ValidateAndProcessFilesAsync( new[] { new FileInformation( filePathJson, "json" ) } );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 1, logContainers.Count, "1 LogContainers expected" );

            const string assemblyName = "microsoft.csharp";

            var expected = new[] {
                $"Name: {assemblyName}, Version: 4.5.0",
                $"~ CPE : No matching CPEs were found for {assemblyName}",
                $"Name: {assemblyName}, Version: 4.7.0",
                $"~ CPE : No matching CPEs were found for {assemblyName}",
                $"~ PURL: pkg:nuget/{assemblyName}@4.5.0",
                $"~ PURL: pkg:nuget/{assemblyName}@4.7.0"   };

            var messages = logContainers.First().Value;
            ValidateLogOutput( expected, messages, false );
        }

        [Test]
        public async Task ValidateAndProcessFilesAsync_EmptyFileProvided_ProcessingSuccess()
        {
            var filePathJson = Path.Combine( AppPath!, "SampleFiles\\bom - Empty.json" );

            var infoExtractor = new InformationExtractor();
            var fileManipulator = new FileManipulator(); 
            var setup = new Setup( new Collection<IExplorer>(), fileManipulator, infoExtractor );

            await setup.ValidateAndProcessFilesAsync( new[] { new FileInformation( filePathJson, "json" ) } );

            var logContainers = ReflectionHelpers.GetLogContainers();
            Assert.AreEqual( 0, logContainers.Count, "0 LogContainers expected" );

            var componentNames = new List<string>();
            var extractedInfo = infoExtractor.ExtractInfo( filePathJson, componentNames );

            Assert.IsEmpty( extractedInfo, $"Expected return from ExtractInfo to be empty but it was not len: {extractedInfo.Count}" );
        }

    }

}

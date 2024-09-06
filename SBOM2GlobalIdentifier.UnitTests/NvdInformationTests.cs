using Sbom2GlobalIdentifier.UnitTests.Helpers;

namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    internal class NvdInformationTests : TestBase
    {
        [SetUp]
        public void Setup() => ResetLogEntries();

        [Test]
        public async Task ExploreAsync_QueryNvdInfo_NoMatchingCPE()
        {
            const string assemblyName = "automapper";
            const string assemblyVersion = "6.2.2";

            var record = new Record
            {
                AssemblyName = assemblyName,
                AssemblyVersion = assemblyVersion
            };

            var cpeExplorer = new CpeExplorer();
            await cpeExplorer.ExploreAsync( new[] { record } );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 1, logContainers.Count, "1 LogContainer expected" );
            var messages = logContainers.First().Value;
            var expected = new[] { $"Name: {assemblyName}, Version: {assemblyVersion}", $"~ CPE : No matching CPEs were found for {assemblyName}" };
            ValidateLogOutput( expected, messages, false );
        }

        [Test]
        public async Task ExploreAsync_QueryNvdInfo_ExactCPEMatch()
        {
            const string assemblyName = "sharpziplib";
            const string assemblyVersion = "1.3.1";

            var record = new Record
            {
                AssemblyName = assemblyName,
                AssemblyVersion = assemblyVersion
            };

            var cpeExplorer = new CpeExplorer();
            await cpeExplorer.ExploreAsync( new[] { record } );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 1, logContainers.Count, "1 LogContainer expected" );
            var messages = logContainers.First().Value;
            var expected = new[]
            {
                $"Name: {assemblyName}, Version: {assemblyVersion}"  ,
                "~ CPE : CPE with (**** EXACT VERSION MATCH ****) found"   ,
                $"~ CPE : cpe:2.3:a:sharpziplib_project:{assemblyName}:1.3.1:*:*:*:*:*:*:*"
            };

            ValidateLogOutput( expected, messages, false );
        }

        [Test]
        public async Task ExploreAsync_QueryNvdInfo_CPEVersionMismatch()
        {
            const string assemblyName = "sharpziplib";
            const string assemblyVersion = "1.4.1";

            var record = new Record
            {
                AssemblyName = assemblyName,
                AssemblyVersion = assemblyVersion
            };

            var cpeExplorer = new CpeExplorer();
            await cpeExplorer.ExploreAsync( new[] { record } );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 1, logContainers.Count, "1 LogContainer expected" );
            var messages = logContainers.First().Value;
            var expected = new[]
            {
                $"Name: {assemblyName}, Version: {assemblyVersion}",
                "~ CPE : CPEs with (**** VERSION MISMATCH ****) found",
                $"~ CPE : cpe:2.3:a:sharpziplib_project:{assemblyName}:-:*:*:*:*:*:*:*"
            };
            ValidateLogOutput( expected, messages, false );
        }

        [Test]
        public async Task ExploreAsync_QueryNvdInfo_CPEPartialNameMatch()
        {
            const string assemblyName = "unity";
            const string assemblyVersion = "4.0.1";

            var record = new Record
            {
                AssemblyName = assemblyName,
                AssemblyVersion = assemblyVersion
            };
            var cpeExplorer = new CpeExplorer();
            await cpeExplorer.ExploreAsync( new[] { record } );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 1, logContainers.Count, "1 LogContainer expected" );
            var messages = logContainers.First().Value;
            // based on what the service returned at the moment of tests writing. Maybe at some point another list will be returned and 
            // first 5 entries will be other.
            var expected = new[]
            {
                $"Name: {assemblyName}, Version: {assemblyVersion}",
                "~ CPE : CPEs with (**** POTENTIAL MATCH ****) found",
                "~ CPE : cpe:2.3:h:cisco:80-7111-01_for_the_unity-svrx255-1a:-:*:*:*:*:*:*:*",
                "~ CPE : cpe:2.3:h:cisco:80-7112-01_for_the_unity-svrx255-2a:-:*:*:*:*:*:*:*",
                "~ CPE : cpe:2.3:h:cisco:unity_express:-:*:*:*:*:*:*:*",
                "~ CPE : cpe:2.3:h:cisco:unity_server:-:*:*:*:*:*:*:*",
                "~ CPE : cpe:2.3:h:cisco:unity_express:1.1.1:*:*:*:*:*:*:*",
                "~ CPE : cpe:2.3:a:ayatana_project:unity:7.2.1:*:*:*:*:*:*:*"
            };
            ValidateLogOutput( expected, messages, false );
        }

        [Test]
        public static async Task RetryApiQeuryAsync__SuccessfulResponse()
        {
            const string assemblyName = "unity";
            const string assemblyVersion = "4.0.1";

            var cpeExplorer = new CpeExplorer();
            var result = await cpeExplorer.RetryApiQueryAsync( assemblyName, assemblyVersion, 1, 10 );

            Assert.IsNotNull( result );
        }
    }
}

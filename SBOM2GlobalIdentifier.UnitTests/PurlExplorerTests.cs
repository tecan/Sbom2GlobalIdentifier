using Sbom2GlobalIdentifier.UnitTests.Helpers;

namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    internal class PurlExplorerTests : TestBase
    {
        [SetUp]
        public void Setup() => 
            ResetLogEntries();

        [Test]
        public async Task ExploreAsync_RecordProvided_NoHits()
        {
            const string recordName = "TestGateKeeper";
            const string recordVersion = "2.5";
            var records = new[] { new Record( recordName, recordVersion ) }; // not existing, even if we decide to publish it

            var crawler = new PurlExplorer();

            await crawler.ExploreAsync( records );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 1, logContainers.Count, "1 LogContainer expected" );
            var messages = logContainers.First().Value;
            var expected = new[] { $"~ PURL: No hits for Name: {recordName} with Version: {recordVersion} (NuGet + NPM)" };
            ValidateLogOutput( expected, messages, false );

        }

        [Test]
        public async Task ExploreAsync_RecordProvided_ExactNPMMatch()
        {
            const string recordName = "angular-ui-bootstrap";
            const string recordVersion = "2.2.0";
            var records = new[] { new Record( recordName, recordVersion ) };

            var crawler = new PurlExplorer();
            await crawler.ExploreAsync( records );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 1, logContainers.Count, "1 LogContainer expected" );
            var messages = logContainers.First().Value;
            var expected = new[] { $"~ PURL: pkg:npm/{recordName}@{recordVersion}" };
            ValidateLogOutput( expected, messages, false );
        }

        [Test]
        public async Task ExploreAsync_RecordProvided_NearestHitFound()
        {
            const string recordName = "Castle.Core";
            const string recordVersion = "4.5";
            var records = new[] { new Record( recordName, recordVersion ) };   // not existing

            var crawler = new PurlExplorer();
            await crawler.ExploreAsync( records );

            var logContainers = ReflectionHelpers.GetLogContainers();

            Assert.AreEqual( 1, logContainers.Count, "1 LogContainer expected" );
            var messages = logContainers.First().Value;
            var expected = new[] { "~ PURL: Nearest hit was for version:4.4.1 (NuGet)" };
            ValidateLogOutput( expected, messages, false );
        }
    }
}

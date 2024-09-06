using System.Collections.ObjectModel;
using Moq;
using Sbom2GlobalIdentifier;
using Sbom2GlobalIdentifier.UnitTests.Helpers;

namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    internal static class DummyVariables
    {
        internal const string DummyApiKey1 = "12345";
        internal const string DummyApiKey2 = "abcdef";
        internal const string DummyDirPath = "/test/directory";
        internal const string DummyNewDirPath = "testDir123";
        internal const string StringToAvoid = "tecan";
        internal const string DummyMaxRetry = "10";
    }

    public class TestBase
    {
        protected string? AppPath;

        [OneTimeSetUp]
        public void CommonTestBase_OneTimeSetUp() => 
            AppPath = AppDomain.CurrentDomain.SetupInformation.ApplicationBase!;

        protected static void ValidateLogOutput( IList<string> expected, IList<string> actual, bool caseInsensitive )
        {
            Assert.That( actual.Count, Is.EqualTo( expected.Count ), $"{expected.Count} messages expected, got {actual.Count} instead" );
            for( var i = 0; i < actual.Count; i++ )
            {
                var sc = caseInsensitive ? StringComparer.InvariantCultureIgnoreCase : StringComparer.InvariantCulture;
                var equal = sc.Compare( actual[i], expected[i] ) == 0;
                Assert.IsTrue( equal, $"Unexpected message text (#{i}){Environment.NewLine} expected: {expected[i]}, {Environment.NewLine}actual: {actual[i]}" );
            }
        }
        protected static void ResetLogEntries()
        {
            var logContainers = ReflectionHelpers.GetLogContainers();
            logContainers.Clear();
        }
    }
}

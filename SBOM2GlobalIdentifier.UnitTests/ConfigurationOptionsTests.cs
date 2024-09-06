namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    internal class ConfigurationOptionsTests : TestBase
    {

        [Test]
        public void ConfigurationOptions_DefaultValues_AllNull()
        {
            var options = new ConfigurationOptions();

            Assert.IsNull( options.ApiKey );
            Assert.IsNull( options.DirPath );
            Assert.IsNull( options.StringToAvoid );
            Assert.IsNull( options.ResultDirPath );
            Assert.IsNull( options.MaxRetryCount );
        }

        [Test]
        public void ConfigurationOptions_AssignValues_ValuesAssigned()
        {
            var options = new ConfigurationOptions
            {
                ApiKey = DummyVariables.DummyApiKey1,
                DirPath = DummyVariables.DummyDirPath,
                StringToAvoid = DummyVariables.StringToAvoid,
                MaxRetryCount = DummyVariables.DummyMaxRetry,
                ResultDirPath = AppPath!
            };

            Assert.AreEqual( DummyVariables.DummyApiKey1, options.ApiKey );
            Assert.AreEqual( DummyVariables.DummyDirPath, options.DirPath );
            Assert.AreEqual( DummyVariables.StringToAvoid, options.StringToAvoid );
            Assert.AreEqual( DummyVariables.DummyMaxRetry, options.MaxRetryCount );
            Assert.AreEqual( AppPath, options.ResultDirPath );
        }
    }
}

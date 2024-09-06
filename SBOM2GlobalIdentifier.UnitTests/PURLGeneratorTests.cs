using Tecan.Tools.Sbom2GlobalIdentifier.Exceptions;

namespace Tecan.Tools.Sbom2GlobalIdentifier.UnitTests
{
    internal class PURLGeneratorTests
    {
        private const string Prefix = "pkg";
        private const string NpmPackageType = "npm";
        private const string NugetPackageType = "nuget";
        private const string DebianPackageType = "deb";
        private const string RpmPackageType = "rpm";
        private const string GolangPackageType = "golang";

        [Test]
        public void PURLConstruction_NameAndVersionProvided_Successful()
        {
            const string assemblyName = "Newtonsoft.Json";
            const string assemblyVersion = "13.0.1";

            var purl = new PurlGenerator( NugetPackageType, assemblyName, assemblyVersion );
            var purlString = purl.ToString();

            Assert.AreEqual( $"{Prefix}:{NugetPackageType}/{assemblyName}@{assemblyVersion}", purlString, "Unexpected string" );
        }

        [Test]
        public void PURLConstruction_NamespaceProvided_Successful()
        {
            const string assemblyName = "core";
            const string assemblyVersion = "11.1.0";
            const string @namespace = "angular";
            var purl = new PurlGenerator( NpmPackageType, @namespace, assemblyName, assemblyVersion, new SortedDictionary<string, string>(), null );

            var purlString = purl.ToString();

            Assert.AreEqual( $"{Prefix}:{NpmPackageType}/{@namespace}/{assemblyName}@{assemblyVersion}", purlString, "Unexpected string" );
        }

        [Test]
        public void PURLConstruction_QualifiersProvided_Successful()
        {
            const string @namespace = "debian";
            const string packageName = "curl";
            const string packageVersion = "7.50.3-1";
            var qualifiers = new SortedDictionary<string, string> { { "distro", "jessie" }, { "arch", "i386" } };

            var purl = new PurlGenerator( DebianPackageType, @namespace, packageName, packageVersion, qualifiers, null );
            var purlString = purl.ToString();

            Assert.AreEqual( $"{Prefix}:{DebianPackageType}/{@namespace}/{packageName}@{packageVersion}?arch=i386&distro=jessie", purlString, "Unexpected string" );
        }
        [Test]
        public void ParsePURLAttributes_PurlProvided_Successful()
        {
            const string packageNamespace = "fedora";
            const string packageName = "curl";
            const string packageVersion = "7.50.3-1.fc25";
            const string qualifiers = "arch=i386&distro=fedora-25";
            const string purlString = $"{Prefix}:{RpmPackageType}/{packageNamespace}/{packageName}@{packageVersion}?{qualifiers}";

            var purl = new PurlGenerator( purlString );

            Assert.AreEqual( RpmPackageType, purl.PackageType, "Unexpected Type" );
            Assert.AreEqual( packageNamespace, purl.PackageNamespace, "Unexpected namespace" );
            Assert.AreEqual( packageName, purl.PackageName, "Unexpected Name" );
            Assert.AreEqual( packageVersion, purl.PackageVersion, "Unexpected Version" );
            Assert.AreEqual( 2, purl.PackageQualifiers.Count, "2 Qualifiers expected" );
        }

        [Test]
        public void ParsePURL_SubpathProvided_Successful()
        {
            const string packageNamespace = "google.golang.org";
            const string packageName = "genproto";
            const string packageSubpath = "googleapis/api/annotations";
            const string purlString = $"{Prefix}:{GolangPackageType}/{packageNamespace}/{packageName}#{packageSubpath}";

            var purl = new PurlGenerator( purlString );

            Assert.AreEqual( GolangPackageType, purl.PackageType, "Unexpected Type" );
            Assert.AreEqual( packageNamespace, purl.PackageNamespace, "Unexpected namespace" );
            Assert.AreEqual( packageName, purl.PackageName, "Unexpected Name" );
            Assert.AreEqual( null, purl.PackageVersion, "Unexpected Version" );
            Assert.AreEqual( packageSubpath, purl.PackageSubpath, "Unexpected PackageSubpath" );
        }


        [Test]
        public void ParsePURL_InvalidStringProvided_Fails()
        {
            const string invalidPurlString = "not a PURL string";
            _ = Assert.Throws<InvalidPurlException>( () =>
            {
                var purl = new PurlGenerator( invalidPurlString );
            } );
        }

        [Test]
        public void ParsePURL_EmptyStringProvided_Fails()
        {
            const string emptyPurlString = "";
            _ = Assert.Throws<InvalidPurlException>( () =>
            {
                var purl = new PurlGenerator( emptyPurlString );
            } );
        }

        [Test]
        public void ParsePURL_NotEnoughFieldsProvided_Fails()
        {
            const string invalidPurlString = $"{Prefix}:pypi/@1.11.1";
            _ = Assert.Throws<InvalidPurlException>( () =>
            {
                var purl = new PurlGenerator( invalidPurlString );
            } );
        }

        [Test]
        public void ParsePURL_EmptyNameProvided_Fails()
        {
            const string? packageName = null;
            const string packageVersion = "1.0";
            _ = Assert.Throws<InvalidPurlException>( () =>
            {
                var purl = new PurlGenerator( NugetPackageType, packageName, packageVersion );
            } );
        }

    }
}

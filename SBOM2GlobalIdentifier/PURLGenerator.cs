using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Tecan.Tools.Sbom2GlobalIdentifier.Exceptions;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{

    /// <summary>
    /// Provides an object representation of a Package URL and easy access to its parts.
    /// 
    /// A purl is a URL composed of seven components:
    /// scheme:type/namespace/name@version?qualifiers#subpath
    /// 
    /// Components are separated by a specific character for unambiguous parsing.
    /// A purl must NOT contain a URL Authority i.e. there is no support for username,
    /// password, host and port components. A namespace segment may sometimes look
    /// like a host but its interpretation is specific to a type.
    ///
    /// To read full-spec, visit <a href="https://github.com/package-url/purl-spec">
    /// </summary>
    [Serializable]
    public sealed partial class PurlGenerator
    {
        /// <summary>
        /// represents the percent-encoded representation of the '/' and ':' characters
        /// </summary>
        private const string EncodedSlash = "%2F";
        private const string EncodedColon = "%3A";
        private static readonly Regex TypePattern = LocalRegex();

        [GeneratedRegex( "^[a-zA-Z][a-zA-Z0-9.+-]+$", RegexOptions.Compiled )]
        private static partial Regex LocalRegex();

        /// <summary>
        /// The PurlGenerator scheme constant.
        /// </summary>
        public string PackageScheme { get; private set; } = "pkg";

        /// <summary>
        /// The package "type" or package "protocol" such as nuget, npm, nuget, gem, pypi, etc.
        /// </summary>
        public string PackageType { get; private set; }

        /// <summary>
        /// The name prefix such as a Maven groupid, a Docker image owner, a GitHub user or organization.
        /// </summary>
        public string PackageNamespace { get; private set; }

        /// <summary>
        /// The name of the package.
        /// </summary>
        public string PackageName { get; private set; }

        /// <summary>
        /// The version of the package.
        /// </summary>
        public string PackageVersion { get; private set; }

        /// <summary>
        /// Extra qualifying data for a package such as an OS, architecture, a distro, etc.
        /// Qaulifiers are attached after the version in PURL with a leading ? and a & in between to distinguish different qualifiers
        /// Example PURL; pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25
        /// <summary>
        public SortedDictionary<string, string> PackageQualifiers { get; private set; }

        /// <summary>
        /// Extra subpath within a package, relative to the package root.
        /// </summary>
        public string PackageSubpath { get; private set; }

        /// <summary>
        /// Constructs a new PurlGenerator object by parsing the specified string.
        /// </summary>
        /// <param name="purl">A valid package URL string to parse.</param>
        /// <exception cref="InvalidPurlException">Thrown when parsing fails.</exception>
        public PurlGenerator( string purl )
        {
            Parse( purl );
        }

        /// <summary>
        /// Constructs a new PurlGenerator object by specifying only the required
        /// parameters necessary to create a valid PurlGenerator.
        /// </summary>
        /// <param name="type">PackageType of package (i.e. nuget, npm, gem, etc).</param>
        /// <param name="name">PackageName of the package.</param>
        /// <exception cref="InvalidPurlException">Thrown when parsing fails.</exception>
        public PurlGenerator( string type, string name, string version ) : this( type, null, name, version, null, null )
        { }

        /// <summary>
        /// Constructs a new PurlGenerator object.
        /// </summary>
        /// <param name="type">PackageType of package (i.e. nuget, npm, gem, etc).</param>
        /// <param name="namespace">PackageNamespace of package (i.e. group, owner, organization).</param>
        /// <param name="name">PackageName of the package.</param>
        /// <param name="version">PackageVersion of the package.</param>
        /// <param name="qualifiers"><see cref="SortedDictionary{string, string}"/> of key/value pair qualifiers.</param>
        /// @param qualifiers an array of key/value pair qualifiers
        /// @param subpath the subpath string
        /// <exception cref="InvalidPurlException">Thrown when parsing fails.</exception>
        public PurlGenerator( string type, string @namespace, string name, string version, SortedDictionary<string, string> qualifiers, string subpath )
        {
            PackageType = ValidateType( type );
            PackageNamespace = ValidateNamespace( @namespace );
            PackageName = ValidateName( name );
            PackageVersion = version;
            PackageQualifiers = qualifiers;
            PackageSubpath = ValidateSubpath( subpath );
        }

        /// <summary>
        /// remove the leading and trailing slashes that always need to be removed
        /// </summary>
        /// <param name="subpath"></param>
        /// <returns></returns>
        private static string ValidateSubpath( string subpath ) =>
            subpath?.Trim( '/' );

        /// <summary>
        /// Returns a canonicalized representation of the purl.
        /// </summary>
        public override string ToString()
        {
            var purl = new StringBuilder();
            _ = purl.Append( PackageScheme ).Append( ':' );

            if( PackageType != null )
            {
                _ = purl.Append( PackageType );
            }
            _ = purl.Append( '/' );
            if( PackageNamespace != null )
            {
                var encodedNamespace = WebUtility.UrlEncode( PackageNamespace ).Replace( EncodedSlash, "/", StringComparison.Ordinal );
                _ = purl.Append( encodedNamespace ).Append( '/' );
            }
            if( PackageName != null )
            {
                var encodedName = WebUtility.UrlEncode( PackageName ).Replace( EncodedColon, ":", StringComparison.Ordinal );
                _ = purl.Append( encodedName );
            }
            if( PackageVersion != null )
            {
                var encodedVersion = WebUtility.UrlEncode( PackageVersion ).Replace( EncodedColon, ":", StringComparison.Ordinal );
                _ = purl.Append( '@' ).Append( encodedVersion );
            }
            if( PackageQualifiers != null && PackageQualifiers.Count > 0 )
            {
                _ = purl.Append( '?' );
                foreach( var pair in PackageQualifiers )
                {
                    var encodedValue = WebUtility.UrlEncode( pair.Value ).Replace( EncodedSlash, "/", StringComparison.Ordinal );
                    _ = purl.Append( pair.Key.ToLowerInvariant() );
                    _ = purl.Append( '=' );
                    _ = purl.Append( encodedValue );
                    _ = purl.Append( '&' );
                }
                _ = purl.Remove( purl.Length - 1, 1 );
            }
            if( PackageSubpath != null )
            {
                var encodedSubpath = WebUtility.UrlEncode( PackageSubpath ).Replace( EncodedSlash, "/", StringComparison.Ordinal ).Replace( EncodedColon, ":", StringComparison.Ordinal );
                _ = purl.Append( '#' ).Append( encodedSubpath );
            }

            return purl.ToString();
        }

        private void Parse( string purl )
        {
            PerformFirstChecks( purl );

            // This is the purl (minus the scheme) that needs parsed.
            var remainder = purl[4..];

            if( remainder.Contains( '#' ) )
            { // subpath is optional - check for existence
                var index = remainder.LastIndexOf( '#' );
                PackageSubpath = ValidateSubpath( WebUtility.UrlDecode( remainder[( index + 1 )..] ) );
                remainder = remainder[..index];
            }

            if( remainder.Contains( '?' ) )
            { // qualifiers are optional - check for existence
                var index = remainder.LastIndexOf( '?' );
                PackageQualifiers = ValidateQualifiers( remainder[( index + 1 )..] );
                remainder = remainder[..index];
            }

            if( remainder.Contains( '@' ) )
            { // version is optional - check for existence
                var index = remainder.LastIndexOf( '@' );
                PackageVersion = WebUtility.UrlDecode( remainder[( index + 1 )..] );
                remainder = remainder[..index];
            }

            // The 'remainder' should now consist of the type, an optional namespace, and the name
            // Trim '/' ('type')
            remainder = remainder.Trim( '/' );

            var firstPartArray = remainder.Split( '/' );
            if( firstPartArray.Length < 2 )
            { // The array must contain a 'type' and a 'name' at minimum
                throw new InvalidPurlException( "Invalid purl: Does not contain a minimum of a 'type' and a 'name'" );
            }

            PackageType = ValidateType( firstPartArray[0] );
            PackageName = ValidateName( WebUtility.UrlDecode( firstPartArray[^1] ) );

            // Test for namespaces
            if( firstPartArray.Length > 2 )
            {
                var namespaceBuilder = new StringBuilder();
                int i;
                const int tmp = 2;
                for( i = 1; i < firstPartArray.Length - tmp; ++i )
                {
                    _ = namespaceBuilder.Append( firstPartArray[i] );
                    _ = namespaceBuilder.Append( '/' );
                }
                _ = namespaceBuilder.Append( firstPartArray[i] );

                var @namespace = namespaceBuilder.ToString();
                PackageNamespace = ValidateNamespace( WebUtility.UrlDecode( @namespace ) );
            }

        }

        private static void PerformFirstChecks( string purl )
        {
            if( purl == null || string.IsNullOrWhiteSpace( purl ) )
            {
                throw new InvalidPurlException( "Invalid purl: Contains an empty or null value" );
            }

            Uri uri;
            try
            {
                uri = new Uri( purl );
            }
            catch( UriFormatException e )
            {
                throw new InvalidPurlException( $"Invalid purl:${e.Message}" );
            }

            // Check to ensure that none of these parts are parsed. If so, it's an invalid purl.
            if( !string.IsNullOrEmpty( uri.UserInfo ) || uri.Port != -1 )
            {
                throw new InvalidPurlException( "Invalid purl: Contains parts not supported by the purl spec" );
            }

            if( uri.Scheme != "pkg" )
            {
                throw new InvalidPurlException( "The PurlGenerator scheme is invalid" );
            }
        }

        private static string ValidateType( string type ) =>
            type == null || !TypePattern.IsMatch( type )
                ? throw new InvalidPurlException( "The PurlGenerator type specified is invalid" )
                : type.ToLowerInvariant();


        private string ValidateNamespace( string @namespace )
        {
            if( @namespace == null )
            {
                return null;
            }
            else
            {
                return PackageType is "bitbucket" or "github" or "pypi" or "gitlab" ? @namespace.ToLowerInvariant() : @namespace;
            }
        }

        private string ValidateName( string name )
        {
            if( string.IsNullOrEmpty( name ) )
            {
                throw new InvalidPurlException( "The PurlGenerator name specified is invalid" );
            }
            else
            {
                if( PackageType is "bitbucket" or "github" or "gitlab" )
                {
                    return name.ToLowerInvariant();
                }
                else
                {
                    return PackageType == "pypi" ? name.Replace( '_', '-' ).ToLowerInvariant() : name;
                }
            }
        }


        private static SortedDictionary<string, string> ValidateQualifiers( string qualifiers )
        {
            var list = new SortedDictionary<string, string>();
            var pairs = qualifiers.Split( '&' );

            foreach( var pair in pairs.Where( currentPair => currentPair.Contains( '=' ) ) )
            {
                var kvPair = pair.Split( '=' );
                list.Add( kvPair[0], WebUtility.UrlDecode( kvPair[1] ) );
            }
            return list;
        }
    }
}

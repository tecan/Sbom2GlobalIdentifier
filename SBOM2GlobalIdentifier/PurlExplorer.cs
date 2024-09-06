using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{ 
    /// <summary>
    /// deals with component lookups to NVD and NUGET.
    /// </summary>
    public sealed class PurlExplorer : IExplorer
    {
        /// <summary>
        /// the base URI to the Nuget Api
        /// </summary>
        private static readonly Uri BaseNugetUri = new( " https://api.nuget.org/v3-flatcontainer/" );

        /// <summary>
        /// the base URI to the Npm Api
        /// </summary>
        private static readonly Uri BaseNpmUri = new( "https://registry.npmjs.org/" );

        /// <summary>
        /// prefix for every PURL result that is appended to the results file <see cref="FileManipulator._resultFileName"/>
        /// </summary>
        private static readonly string Prefix = new( "~ PURL:" );

        /// <summary>
        /// max retry count for one component before it is skipped. Is currently initialized in <see cref="Setup.InitializeMaxRetryCountBeforeSkip(string))>
        /// </summary>
        internal int MaxRetryCount { get; set; } = 20;

        /// <summary>
        /// conduct a query/lookup for every record present in <paramref name="recordList"/>. The method calls in <see cref="StartQueryAsync(Record)"/> which starts the query.
        /// </summary>
        /// <param name="recordList"></param>
        /// <returns> <see cref="Task"/></returns>
        public async Task ExploreAsync( IEnumerable<Record> recordList )
        {
            if( recordList == null )
            {
                return;
            }

            ConsoleOutput.WriteToConsole( $"\nAttempting to generate PURLs for {recordList.ToList().Count} entries.", ConsoleColor.Yellow );
            var countPurlNotGenerated = 0;

            foreach( var record in recordList )
            {
                countPurlNotGenerated += await StartQueryAsync( record );
            }
            ConsoleOutput.WriteToConsole( $"Generated PURLs for {recordList.ToList().Count - countPurlNotGenerated} entries.", ConsoleColor.Green );
        }


        /// <summary>
        /// start the query with NPM <see cref="QueryNpmAsync(Record,int)"/> and moves on to querying Nuget with <see cref="QueryNuGetAsync(Record, int)"/>
        /// </summary>
        /// <param name="record"></param>
        /// <returns> 1 if no hit was found, 0 if at least one hit was found or if a nearest match was found. We do this to keep track of all the entries (count) for which 
        ///     PURLs were generated</returns>
        private async Task<int> StartQueryAsync( Record record )
        {
            var responseNpm = await QueryNpmAsync( record, 0 );
            var responseNuGet = await QueryNuGetAsync( record, 0 );

            if( responseNpm == ApiQueryResponse.ExactMatch || responseNuGet == ApiQueryResponse.ExactMatch )
            {
                return 0;
            }
            else if( responseNpm == ApiQueryResponse.NoMatch && responseNuGet == ApiQueryResponse.NoMatch )
            {
                FileManipulator.AddToContainer( record.AssemblyName, $"{Prefix} No hits for Name: {record.AssemblyName} with Version: {record.AssemblyVersion} (NuGet + NPM)" );
                return 1;
            }
            else
            {
                return 1;
            }
        }

        /// <summary>
        /// queries NPM for the given <paramref name="record"/> using <see cref="HttpClient.GetAsync(Uri?)"/>.
        /// If the response was successful (<see cref="HttpResponseMessage.IsSuccessStatusCode"/>), then it calls <see cref="ProcessSuccessfulNpmResponse(Record, NpmApiResponse)"/>
        /// else if the response is not successful and the <paramref name="retryCount"/> is less than the max retry Count defined in <see cref="Setup.MaxRetryCount"/>, then it 
        /// calls itself by increasing the retryCount by 1
        /// </summary>
        /// <param name="record"></param>
        /// <returns></returns>
        internal async Task<ApiQueryResponse> QueryNpmAsync( Record record, int retryCount )
        {

            Uri currentUri = new( BaseNpmUri, $"{record.AssemblyName.ToLowerInvariant()}" );
            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync( currentUri );

            var npmResponse = ApiQueryResponse.NoMatch;
            if( response.IsSuccessStatusCode )
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                var resp = JsonSerializer.Deserialize<NpmApiResponse>( responseBody );

                npmResponse = ProcessSuccessfulNpmResponse( record, resp );
            }
            else if( ( response.StatusCode is System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.TooManyRequests ) && retryCount < MaxRetryCount )
            {
                retryCount++;
                _ = await QueryNpmAsync( record, retryCount );
            }
            else
            {
                //pass
            }
            return npmResponse;
        }


        /// <summary>
        /// if the response status is 200, then do the processing accordingly. Create PURL if exact match was found else if a match with major version was found then
        /// let the user know about it but dont create the PURL for it
        /// </summary>
        /// <param name="record"></param>
        /// <param name="resp"></param>
        private static ApiQueryResponse ProcessSuccessfulNpmResponse( Record record, NpmApiResponse resp )
        {
            if( resp != null && resp.Versions != null )
            {
                if( resp.Versions.ContainsKey( record.AssemblyVersion ) )
                {
                    var purl = new PurlGenerator( "npm", record.AssemblyName, record.AssemblyVersion );
                    FileManipulator.AddToContainer( record.AssemblyName, $"{Prefix} {purl}" );
                    return ApiQueryResponse.ExactMatch;
                }
                else
                {
                    var matchingVersions = resp.Versions.Keys
                        ?.Where( v => v != null && record.AssemblyVersion != null &&
                                    v.StartsWith( record.AssemblyVersion.Split( '.' )[0], StringComparison.OrdinalIgnoreCase ) )?.ToList();

                    if( matchingVersions.Count != 0 )
                    {
                        var nearestVersion = matchingVersions.OrderByDescending( v => new Version( v ) ).FirstOrDefault();
                        FileManipulator.AddToContainer( record.AssemblyName, $"{Prefix} Nearest hit was for version:{nearestVersion} (NPM)" );
                    }
                    return ApiQueryResponse.NearestMatch;
                }
            }
            return ApiQueryResponse.NoMatch;
        }


        /// <summary>
        /// implements the same concept as <see cref="QueryNpmAsync(Record, int)"/> but with a slightly different logic
        /// </summary>
        /// <param name="record"></param>
        /// <returns></returns>
        internal async Task<ApiQueryResponse> QueryNuGetAsync( Record record, int retryCount )
        {
            Uri currentUri = new( BaseNugetUri, $"{record.AssemblyName.ToLowerInvariant()}/index.json" );
            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync( currentUri );
            var nugetResponse = ApiQueryResponse.NoMatch;

            if( response.IsSuccessStatusCode )
            {
                var contentString = await response.Content.ReadAsStringAsync();
                var resp = JsonSerializer.Deserialize<NugetApiResponse>( contentString );

                nugetResponse = ProcessSuceessfulNugetResponse( record, in resp );
            }
            else if( ( response.StatusCode is System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.TooManyRequests ) && retryCount < MaxRetryCount )
            {
                retryCount++;
                _ = await QueryNuGetAsync( record, retryCount );
            }
            else
            {
                //pass
            }
            return nugetResponse;
        }


        /// <summary>
        /// if the response status is 200, then do the processing accordingly. Create PURL if exact match was found else if a match with major version was found then
        /// let the user know about it but dont create a PURL for it
        /// </summary>
        /// <param name="record"></param>
        /// <param name="resp"></param>
        private static ApiQueryResponse ProcessSuceessfulNugetResponse( Record record, in NugetApiResponse resp )
        {
            if( resp != null && resp.Versions != null )
            {
                if( resp.Versions.Any( currentVersion => string.Equals( currentVersion, record.AssemblyVersion, StringComparison.OrdinalIgnoreCase ) ) )
                {
                    var purl = new PurlGenerator( "nuget", record.AssemblyName, record.AssemblyVersion );
                    FileManipulator.AddToContainer( record.AssemblyName, $"{Prefix} {purl}" );
                    return ApiQueryResponse.ExactMatch;
                }
                else
                {
                    var nearestVersion = resp.Versions
                    .OrderByDescending( NuGet.Versioning.NuGetVersion.Parse )
                    .FirstOrDefault( version => NuGet.Versioning.NuGetVersion.Parse( version ).Major == NuGet.Versioning.NuGetVersion.Parse( record.AssemblyVersion ).Major );

                    if( nearestVersion != null )
                    {
                        FileManipulator.AddToContainer( record.AssemblyName, $"{Prefix} Nearest hit was for version:{nearestVersion} (NuGet)" );
                    }
                    return ApiQueryResponse.NearestMatch;
                }
            }
            return ApiQueryResponse.NoMatch;
        }

    }



    [Serializable]
    public class NugetApiResponse
    {
        [JsonPropertyName( "versions" )]
        public IEnumerable<string> Versions { get; set; }
    }


    [Serializable]
    public class NpmApiResponse
    {
        [JsonPropertyName( "versions" )]
        public Dictionary<string, NpmVersionInfo> Versions { get; set; }
    }

    public class NpmVersionInfo
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public string Description { get; set; }
    }

}


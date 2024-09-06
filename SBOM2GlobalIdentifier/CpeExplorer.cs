using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    /// <summary>
    /// deals with API calls to NVD for CPE lookup purposes
    /// </summary>
    public sealed class CpeExplorer : IExplorer
    {
        /// <summary>
        /// <see cref="ApiKey"/> is used during <see cref="HttpClient.GetAsync(Uri?)"/> requests to NVD. if this attribute is set, then the sleep interval between 
        /// the requests is considerably lower than if the ApiKey is not present since NVD currently only allows for 5 requests per rolling 30 second window if 
        /// no API Key is provided. See <see cref="DetermineSleepInterval"/> for a clearer understanding of the sleep intervals
        /// </summary>
        public string ApiKey { get; set; }

        /// <summary>
        /// prefix for every CPE result that is appended to the results file <see cref="FileManipulator._resultFileName"/>
        /// </summary>
        public static readonly string CpePrefix = new( "~ CPE :" );

        /// <summary>
        /// the base API endpoint used for CPE lookups
        /// </summary>
        private static readonly Uri BaseNvdUri = new( $"https://services.nvd.nist.gov/rest/json/cpes/2.0" );

        /// <summary>
        /// if somehow the API rate limit is exceeded, then wait <see cref="WaitTimeSecondsIfResponseForbidden"/> seconds before sending another request 
        /// </summary>
        private const int WaitTimeSecondsIfResponseForbidden = 60;

        /// <summary>
        /// if an error not related to the API rate limit occured, then wait <see cref="WaitTimeSecondsIfGeneralError"/> seconds before sending another request 
        /// </summary>
        private const int WaitTimeSecondsIfGeneralError = 10;

        /// <summary>
        /// max retry count for one component before it is skipped. Is currently initialized in <see cref="Setup.InitializeMaxRetryCountBeforeSkip(string))>
        /// </summary>
        internal int MaxRetryCount { get; set; } = 20;

        /// <summary>
        /// take all the Assembly Information gathered and uses them to do the API requests pair by pair 
        /// </summary>
        /// <param name="recordList"></param>
        /// <returns></returns>
        public async Task ExploreAsync( IEnumerable<Record> recordList )
        {
            var totalTasks = recordList.Count();
            var currentTask = 0;
            if( recordList.Any() )
            {
                foreach( var csvRecord in recordList )
                {
                    currentTask++;
                    await ApiQueryAsync( csvRecord.AssemblyName.ToLowerInvariant(), csvRecord.AssemblyVersion.ToLowerInvariant(), 0 );
                    Setup.UpdateProgressBar( totalTasks, currentTask );
                }
            }
        }

        /// <summary>
        /// sends an API request using the endpoint <see cref="BaseNvdUri"/> by considering the sleep interval. Calls 
        /// <see cref="CheckResponseStatusAsync(HttpResponseMessage, string, string, int)"/> to process the response received from the API
        /// </summary>
        /// <param name="assemblyName">name of the assembly for which CPE lookup is to be performed</param>
        /// <param name="assemblyVersion"> version of <paramref name="assemblyName"/>"/ which will be used to determine the match type></param>
        /// <param name="retryCount"> number of times the request has been sent for this pair of <paramref name="assemblyName"/> & 
        ///         <paramref name="assemblyVersion"/></param>
        /// <returns></returns>
        public async Task ApiQueryAsync( string assemblyName, string assemblyVersion, int retryCount )
        {
            try
            {
                var encodedAssemblyName = Uri.EscapeDataString( assemblyName );
                Uri apiUrl = new( BaseNvdUri, $"?keywordSearch={encodedAssemblyName}&keywordExactMatch" );

                DisplayRequestInfoBasedOnRetryCount( apiUrl, assemblyName, assemblyVersion, retryCount );

                var httpClient = new HttpClient();
                if( !string.IsNullOrEmpty( ApiKey ) )
                {
                    httpClient.DefaultRequestHeaders.Add( "apiKey", ApiKey );
                }

                await Task.Delay( DetermineSleepInterval() );

                var response = await httpClient.GetAsync( apiUrl );

                await CheckResponseStatusAsync( response, assemblyName, assemblyVersion, retryCount );
            }
            catch( Exception e ) when( e.InnerException != null )
            {
                _ = await RetryApiQueryAsync( assemblyName, assemblyVersion, retryCount, WaitTimeSecondsIfGeneralError );
            }
        }

        /// <summary>
        /// only purpose is to display the request message which includes a browser friendly URL to the user, given this is the first request being sent for 
        /// this pair of <paramref name="assemblyName"/> and <paramref name="assemblyVersion"/>
        /// </summary>
        /// <param name="apiUrl">API Endpoint to which the request is being sent</param>
        /// <param name="assemblyName">name of the assembly for which the request is being sent</param>
        /// <param name="assemblyVersion">versio of the <paramref name="assemblyName"/> for which the request is being sent</param>
        /// <param name="retryCount">number of times the request has been sent for this pair of <paramref name="assemblyName"/> & 
        ///     <paramref name="assemblyVersion"/></param>
        private static void DisplayRequestInfoBasedOnRetryCount( Uri apiUrl, string assemblyName, string assemblyVersion, int retryCount )
        {
            if( retryCount == 0 )
            {
                //to give a better representation, replace spaces explicitly with %20
                var displayUrl = apiUrl.ToString().Replace( " ", "%20", StringComparison.InvariantCultureIgnoreCase );
                ConsoleOutput.WriteToConsole( $"\n\nRequesting {displayUrl}\nName:{assemblyName}\nVersion:{assemblyVersion}" );
            }
        }

        /// <summary>
        /// If the reponse is successful (<see cref="HttpResponseMessage.IsSuccessStatusCode"/>), then add the corresponding pair of the 
        /// <paramref name="assemblyName"/> and <paramref name="assemblyVersion"/>to the dictionary and process the response received by calling 
        /// <see cref="ProcessCpeResponse(in JObject, string, string)"/>
        /// But if the response was not successful then let the user know and call <see cref="RetryApiQueryAsync(string, string, int, int)"/> which 
        /// internally waits for the specified duration.
        /// </summary>
        /// <param name="response"></param>
        /// <param name="assemblyName"></param>
        /// <param name="assemblyVersion"></param>
        /// <param name="retryCount"></param>
        /// <returns</returns>
        private async Task CheckResponseStatusAsync( HttpResponseMessage response, string assemblyName, string assemblyVersion, int retryCount )
        {
            if( response.IsSuccessStatusCode )
            {
                FileManipulator.AddToContainer( assemblyName, $"Name: {assemblyName}, Version: {assemblyVersion}" );
                var responseContent = await response.Content.ReadAsStringAsync();
                var cpeData = JsonConvert.DeserializeObject<JObject>( responseContent );
                ProcessCpeResponse( cpeData, assemblyName, assemblyVersion );
            }
            else if( response.StatusCode is System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.TooManyRequests )
            {
                if( retryCount < MaxRetryCount )
                {
                    ConsoleOutput.WriteToConsole( $"Latest response had status code '{response.StatusCode}' which typically means the rate limit has been reached.\n" +
                    $"Waiting {WaitTimeSecondsIfResponseForbidden} seconds before trying again....", ConsoleColor.Yellow );
                    ConsoleOutput.WriteToConsole( Constants.CONSIDER_APPLYING_FOR_AN_API_KEY );
                    _ = await RetryApiQueryAsync( assemblyName, assemblyVersion, retryCount, WaitTimeSecondsIfResponseForbidden );
                }
                else
                {
                    ConsoleOutput.WriteToConsole( $"INFO: Max retry count ({MaxRetryCount}) reached for {assemblyName}, skipping this component", ConsoleColor.Yellow );
                }
            }
            else
            {
                if( retryCount < MaxRetryCount )
                {
                    _ = await RetryApiQueryAsync( assemblyName, assemblyVersion, retryCount, WaitTimeSecondsIfGeneralError );
                }
                else
                {
                    ConsoleOutput.WriteToConsole( $"INFO: Max retry count ({MaxRetryCount}) reached for {assemblyName}, skipping this component", ConsoleColor.Yellow );
                }
            }
        }

        /// <summary>
        /// called if the initial request to the API done by <see cref="ApiQueryAsync(string, string, int)"/> fails.
        /// Calls <see cref="ApiQueryAsync(string, string, int)"/> internally by waiting the duration specified in <paramref name="waitTimeSeconds"/>
        /// </summary>
        /// <param name="assemblyName"></param>
        /// <param name="assemblyVersion"></param>
        /// <param name="retryCount"></param>
        /// <param name="waitTimeSeconds"></param>
        /// <returns></returns>
        public async Task<bool> RetryApiQueryAsync( string assemblyName, string assemblyVersion, int retryCount, int waitTimeSeconds )
        {
            retryCount++;

            await Task.Delay( TimeSpan.FromSeconds( waitTimeSeconds ) );

            const int linesToErase = 1;
            const int maxRetryCountBeforeLineErasure = 2;

            //need the whole Console. thing because unit tests will fail without it
            if( retryCount >= maxRetryCountBeforeLineErasure && !Console.IsOutputRedirected && !Console.IsInputRedirected && !Console.IsErrorRedirected )
            {
                Console.SetCursorPosition( 0, Console.CursorTop - linesToErase );
            }
            ConsoleOutput.WriteToConsole( $"Request failed for entry '{assemblyName}', retrying....({retryCount})", ConsoleColor.Yellow );

            await ApiQueryAsync( assemblyName, assemblyVersion, retryCount );
            return true;
        }

        /// <summary>
        /// determines the delay between requests depending on if <see cref="ApiKey"/> is set
        /// </summary>
        /// <returns></returns>
        private int DetermineSleepInterval()
        {
            const int defaultSleepInterval = 6500;
            const int sleepIntervalWithApiKey = 1000;

            return !string.IsNullOrEmpty( ApiKey ) ? sleepIntervalWithApiKey : defaultSleepInterval;
        }


        /// <summary>
        /// If the array products in <paramref name="cpeData"/> is empty, then that means no match was found else a match, either perfect or 
        /// close, has been found.
        /// if no match was found in the response array, then it calls <see cref="NoMatchFoundInResponse(string)"/>
        /// else if some kind of a match was found, then it calls <see cref="MatchFoundInResponse(in JObject, string, string)"/> 
        /// </summary>
        /// <param name="cpeData"></param>
        /// <param name="assemblyName"></param>
        /// <param name="assemblyVersion"></param>
        private static void ProcessCpeResponse( in JObject cpeData, string assemblyName, string assemblyVersion )
        {
            if( cpeData != null && cpeData["products"].HasValues )
            {
                MatchFoundInResponse( cpeData, assemblyName, assemblyVersion );
            }
            else
            {
                NoMatchFoundInResponse( assemblyName );
            }
        }

        /// <summary>
        /// lets the user know that no match was found and calls <see cref="FileManipulator.AddToContainer(string, string)"/> to append the entries to the dict.
        /// </summary>
        /// <param name="assemblyName"></param>
        /// <param name="assemblyVersion"></param>
        internal static void NoMatchFoundInResponse( string assemblyName )
        {
            var message = $"{Constants.NO_CPES_FOUND} for {assemblyName}";
            ConsoleOutput.WriteToConsole( message, ConsoleColor.Red );
            FileManipulator.AddToContainer( assemblyName, string.Concat( CpePrefix, $" {message}" ) );
        }

        /// <summary>
        /// if match was found, check whether it was an exact match or there was a version mismatch and process it accordingly
        /// if exact match was not found, deviate the processing to <see cref="MatchFoundWithDifferences(in JArray, string)"/>
        /// </summary>
        /// <param name="cpeData"></param>
        /// <param name="assemblyName"></param>
        /// <param name="assemblyVersion"></param>
        private static void MatchFoundInResponse( in JObject cpeData, string assemblyName, string assemblyVersion )
        {

            var products = (JArray)cpeData?["products"];
            var exactMatchFound = ProductTokenAnalyzer.AnalyzeExact( products, assemblyName, assemblyVersion );

            //for version mismatch but CPE existing
            if( !exactMatchFound )
            {
                MatchFoundWithDifferences( products, assemblyName );
            }
        }

        /// <summary>
        /// There are 2 cases. One where the CPE was found for the assemblyName but the version differed and another where a "potentiallly matching" CPE was found.
        /// This potentially found CPE might not necessarily have the same assemblyName but its important to mention that it exists
        /// </summary>
        /// <param name="assemblyName"></param>
        /// <param name="products"></param>
        /// <param name="assemblyVersion"></param>
        private static void MatchFoundWithDifferences( in JArray products, string assemblyName )
        {
            if( products != null )
            {
                var analyzer = new ProductTokenAnalyzer();
                analyzer.AnalyzeWithDifferences( products, assemblyName );
            }
            else
            {
                //pass
            }
        }

    }

}

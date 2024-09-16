using System;
using Newtonsoft.Json.Linq;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    internal class ProductTokenAnalyzer
    {
        private bool _hasPotentialSentenceBeenPrinted;
        private int _potentialEntryCount;
        private bool _hasNoMatchFoundBeenProcessedOnce;

        private const int ASSEMBLY_NAME_IDX = 4;            // index of assembly name in the string sent in cpeName
        private const int ASSEMBLY_VERSION_IDX = 5;         // index of assembly version in the string sent in cpeName
        private const int EXPECTED_ELEMENT_LENGTH = 6;

        //private const int MAX_ENTRY_COUNT = 5;

        private const string CPE_ELEMENT = "cpe";
        private const string CPE_NAME_ELEMENT = "cpeName";

        /// <summary>
        /// is basically called as the first method for every response from the API.it analyzes if the assemblyName and version that we have corresponds to the response from the API
        /// and if both the name and the version match then that means an exact match has been found in the database
        /// </summary>
        /// <param name="products"></param>
        /// <param name="assemblyName"></param>
        /// <param name="assemblyVersion"></param>
        /// <returns></returns>
        public static bool AnalyzeExact( JArray products, string assemblyName, string assemblyVersion )
        {
            var exactMatchFound = false;

            foreach( var productToken in products )
            {
                var product = (JObject)productToken;
                var cpe = (JObject)product[CPE_ELEMENT];
                var cpeName = cpe[CPE_NAME_ELEMENT]?.ToString();
                var cpeElements = cpeName.Split( ':' );

                if( cpeElements != null && cpeElements.Length >= EXPECTED_ELEMENT_LENGTH
                    && cpeElements[ASSEMBLY_NAME_IDX] == assemblyName
                    && cpeElements[ASSEMBLY_VERSION_IDX] == assemblyVersion )
                {
                    exactMatchFound = true;
                    ConsoleOutput.WriteToConsole( Constants.EXACT_MATCH, ConsoleColor.Green );
                    ConsoleOutput.WriteToConsole( $"{cpeName}\n", ConsoleColor.Green );
                    FileManipulator.AddToContainer( assemblyName, $"{CpeExplorer.CpePrefix} {Constants.EXACT_MATCH}" );
                    FileManipulator.AddToContainer( assemblyName, $"{CpeExplorer.CpePrefix} {cpeName}" );
                }
            }

            return exactMatchFound;
        }

        /// <summary>
        /// if <see cref="AnalyzeExact(JArray, string, string)"/> returned false, then this is the next step. basically checks if the assemblyName corresponds to the response from the API
        /// </summary>
        /// <param name="products"></param>
        /// <param name="assemblyName"></param>
        public void AnalyzeWithDifferences( JArray products, string assemblyName )
        {
            _hasPotentialSentenceBeenPrinted = false;
            _potentialEntryCount = 0;
            _hasNoMatchFoundBeenProcessedOnce = false;

            foreach( var productToken in products )
            {
                var nameMatched = ProcessProductToken( productToken, assemblyName );
                if( nameMatched )
                {
                    // we have nothing to do after the loop, can return from here
                    return;
                }
            }
        }

        /// <summary>
        /// processes the response from the NVD Api.
        /// if the <paramref name="assemblyName"/> equals the string in the response <paramref name="productToken"/> in the specified index <see cref="ASSEMBLY_NAME_IDX"/>, 
        /// then consider it as a name match and call <see cref="ProcessNameMatch(string[], string)"/>
        /// else if the <paramref name="assemblyName"/> is a substring in the response <paramref name="productToken"/> in the specified index <see cref="ASSEMBLY_NAME_IDX"/>,
        /// consider it as a partial match and call <see cref="ProcessNamePartialMatch(string[], string)"/>
        /// else no match was found in the response <paramref name="productToken"/> for the assembly <paramref name="assemblyName"/>, call 
        /// <see cref="CpeExplorer.NoMatchFoundInResponse(string)"/>
        /// </summary>
        /// <param name="productToken"></param>
        /// <param name="assemblyName"></param>
        /// <returns></returns>
        private bool ProcessProductToken( JToken productToken, string assemblyName )
        {
            var product = (JObject)productToken;
            var cpe = (JObject)product[CPE_ELEMENT];
            var cpeName = cpe?[CPE_NAME_ELEMENT]?.ToString();
            var cpeElements = cpeName?.Split( ':' );

            if( cpeElements == null || cpeElements?.Length < EXPECTED_ELEMENT_LENGTH )
            {
                return false;
            }

            // CPE with version mismatch match found
            if( cpeElements[ASSEMBLY_NAME_IDX] == assemblyName )
            {
                ProcessNameMatch( cpeElements, assemblyName );
                return true;
            }
            //potential CPE found  
            else if( cpeElements[ASSEMBLY_NAME_IDX].Contains( assemblyName, StringComparison.OrdinalIgnoreCase ) )
            {
                ProcessNamePartialMatch( cpeElements, assemblyName );
            }
            else
            {
                if( !_hasNoMatchFoundBeenProcessedOnce )
                {
                    CpeExplorer.NoMatchFoundInResponse( assemblyName );
                }
                _hasNoMatchFoundBeenProcessedOnce = true;
            }
            return false;
        }

        private void ProcessNameMatch( string[] cpeElements, string assemblyName )
        {
            if( !_hasPotentialSentenceBeenPrinted )
            {
                ConsoleOutput.WriteToConsole( Constants.MATCH_WITH_VERSION_MISMATCH, ConsoleColor.Yellow );
                FileManipulator.AddToContainer( assemblyName, $"{CpeExplorer.CpePrefix} {Constants.MATCH_WITH_VERSION_MISMATCH}" );
            }
            ConsoleOutput.WriteToConsole( $"{CpeExplorer.CpePrefix} {string.Join( ":", cpeElements )}", ConsoleColor.Yellow );
            FileManipulator.AddToContainer( assemblyName, $"{CpeExplorer.CpePrefix} {string.Join( ":", cpeElements )}" );
        }

        private void ProcessNamePartialMatch( string[] cpeElements, string assemblyName )
        {
            if( !_hasPotentialSentenceBeenPrinted )
            {
                ConsoleOutput.WriteToConsole( Constants.POTENTIAL_MATCH, ConsoleColor.Yellow );
                FileManipulator.AddToContainer( assemblyName, $"{CpeExplorer.CpePrefix} {Constants.POTENTIAL_MATCH}" );
                _hasPotentialSentenceBeenPrinted = true;
            }
            ConsoleOutput.WriteToConsole( $"{string.Join( ":", cpeElements )}", ConsoleColor.Yellow );

            //if( _potentialEntryCount < MAX_ENTRY_COUNT )
            //{
            FileManipulator.AddToContainer( assemblyName, $"{CpeExplorer.CpePrefix} {string.Join( ":", cpeElements )}" );
            _potentialEntryCount++;
            //}
        }
    }
}

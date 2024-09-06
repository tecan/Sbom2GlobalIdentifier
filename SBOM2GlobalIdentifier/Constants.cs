namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    /// <summary>
    /// all the constants used within the application
    /// </summary>
    public static class Constants
    {
        public static readonly string FILE_FORMAT_NOT_SUPPORTED = "This file format is not supported (use a valid SBOM file in JSON format)";
        public static readonly string NO_FILE_FOUND = "No JSON file present in the current directory";
        public static readonly string NO_CPES_FOUND = "No matching CPEs were found";
        public static readonly string INPUT_FULL_PATH_TO_FILE = "Full Path to the json file you wish to use:";
        public static readonly string INTERNALLY_CREATED_CSV = "Internally created CSV";
        public static readonly string NO_ASSEMBLY_INFO_PRESENT = "No assembly information present";
        public static readonly string EXECUTION_COMPLETE = "Execution complete.";
        public static readonly string GENERAL_ERROR = "A General Error Occurred";
        public static readonly string FILE_NOT_FOUND = "Files not found";
        public static readonly string WRITE_ERROR = "Couldn't write to file:";
        public static readonly string MATCH_WITH_VERSION_MISMATCH = "CPEs with (**** VERSION MISMATCH ****) found";
        public static readonly string EXACT_MATCH = "CPE with (**** EXACT VERSION MATCH ****) found";
        public static readonly string NO_MATCH = "(**** NO MATCH ****)";
        public static readonly string ERROR_DURING_REQUEST = "(**** ERROR DURING REQUEST ****)";
        public static readonly string TMP_LOG_FILE_PATH = "tmp.txt";
        public static readonly string POTENTIAL_MATCH = "CPEs with (**** POTENTIAL MATCH ****) found";
        public static readonly string BOM_DATA_NULL = "bomData was null, check if your JSON file is in correct format";
        public static readonly string NO_API_KEY = "INFO: No Api Key has been provided, requests are restricted to 5 requests per rolling 30 second window.";
        public static readonly string CONSIDER_APPLYING_FOR_AN_API_KEY = "Consider applying for a free Api key at https://nvd.nist.gov/developers/request-an-api-key";
        public static readonly string API_KEY_PRESENT = "INFO: Api Key has been provided, sending 1 request per second.";
        public static readonly string ERROR_CREATING_CSV_FILE = "Error creating CSV file:";
        public static readonly string NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD.";
        public static readonly string NOT_IMPLEMENTED_ERROR = "General Error occurred during Csv Creation";
        public static readonly string SECRETS_FILE = "nvd_accelerator.txt";
        public static readonly string FAULTY_OPTIONS_PROVIDED = "FATAL: The provided option(s) are not valid, type --help to see the list of available options";
        public static readonly string LINE = "\n--------------------------------------------------------------------------------------------------------------------\n";
    }


}

using CommandLine;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    /// <summary>
    /// All the Command Line Arguments that the user can pass to the tool. character denoted inside '' represent the shortcut for the option defined inside ""
    /// For example: -a 123456 is the same as saying --apiKey 123456, -x apple is the same as saying --exclude apple
    /// When Required is set to true, the option becomes mandatory
    /// </summary>
    public class ConfigurationOptions
    {
        [Option( 'a', "apiKey", Required = false, Default = null, HelpText = "The Api Key to NVD for CPE Lookups." )]
        public string ApiKey { get; set; }

        [Option( 'd', "dirPath", Required = false, Default = null, HelpText = "Path to the directory containing valid SBOM file(s) in JSON format." )]
        public string DirPath { get; set; }

        [Option( 'x', "exclude", Required = false, Default = null, HelpText = "Components that contain this string will not be used for further processing.Refer" +
            "to the documentation for a better understanding." )]
        public string StringToAvoid { get; set; }

        [Option( 'r', "resultPath", Required = false, Default = null, HelpText = "Path to the directory where you want the log files to go, if not specified the log files" +
            "will be created in the CWD of the tool." )]
        public string ResultDirPath { get; set; }

        [Option( 'm', "maxRetryCount", Required = false, Default = "20", HelpText = "Maximum number of retries for a specific assembly. If not assigned, the max retry Count will" +
            "default to 20" )]
        public string MaxRetryCount { get; set; }

    }
}

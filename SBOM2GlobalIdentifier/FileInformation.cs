namespace Tecan.Tools.Sbom2GlobalIdentifier
{ 
    public class FileInformation
    {
        public FileInformation( string fileName, string fileType )
        {
            FileName = fileName;
            FileType = fileType;
        }
        public string FileName { get; set; }
        public string FileType { get; set; }
    }
}

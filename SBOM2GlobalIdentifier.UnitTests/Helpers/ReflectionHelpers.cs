using System.Reflection;
using Tecan.Tools.Sbom2GlobalIdentifier;

namespace Sbom2GlobalIdentifier.UnitTests.Helpers
{
    internal class ReflectionHelpers
    {
        public static Dictionary<string, List<string>> GetLogContainers()
        {
            Dictionary<string, List<string>>? result;

            var type = typeof( FileManipulator );
            var fieldInfo = type.GetField( "LoggingContainer", BindingFlags.NonPublic | BindingFlags.Static );

            if( fieldInfo != null )
            {
                var value = fieldInfo.GetValue( null );
                result = value as Dictionary<string, List<string>>;
            }
            else
            {
                throw new InvalidOperationException( "Fatal: logging container was null, check if the attribute name has been changed and try again." );
            }
            return result!;
        }
    }
}

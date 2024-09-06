using System.Collections.Generic;
using System.Threading.Tasks;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    public interface IExplorer
    {
        public Task ExploreAsync( IEnumerable<Record> recordList );
    }
}

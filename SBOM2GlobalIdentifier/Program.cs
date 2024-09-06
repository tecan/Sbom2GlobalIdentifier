using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    public static class Program
    {
        public static async Task Main( string[] args )
        {
            var serviceProvider = new ServiceCollection()
            .AddSingleton<IExplorer, CpeExplorer>()
            .AddSingleton<IExplorer, PurlExplorer>()
            .AddSingleton<FileManipulator>()
            .AddSingleton<InformationExtractor>()
            .AddTransient<Setup>()
            .BuildServiceProvider();

            var setup = serviceProvider.GetService<Setup>();
            await setup.RunAsync( args );
        }
    }
}

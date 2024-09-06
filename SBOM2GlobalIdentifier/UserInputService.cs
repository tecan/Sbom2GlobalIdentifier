using System;

namespace Tecan.Tools.Sbom2GlobalIdentifier 
{ 
    public interface IUserInputService
    {
        public string ReadLine();
    }

    public class UserInputService : IUserInputService
    {
        public string ReadLine() => Console.ReadLine();
    }
}

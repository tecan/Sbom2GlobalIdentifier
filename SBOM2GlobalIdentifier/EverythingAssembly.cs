using System;
using System.Collections.Generic;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    public class Record
    {
        public Record() { }
        public Record( string assemblyName, string assemblyVersion )
        {
            AssemblyName = assemblyName;
            AssemblyVersion = assemblyVersion;
        }
        public string AssemblyName { get; set; }
        public string AssemblyVersion { get; set; }
    }

    /// <summary>
    /// used to deserialize the sbom file from json to class format
    /// </summary>
    [Serializable]
    public class BomData
    {
        public IEnumerable<Components> Components { get; set; } = Array.Empty<Components>();
        public Metadata MetaData { get; set; }
    }

    public class Components
    {
        public string Name { get; set; }
        public string Version { get; set; }
    }

    /// <summary>
    /// extract the name of the project/component to be later used in the log file
    /// </summary>
    public class Metadata
    {
        public Component Component { get; set; }
    }

    public class Component
    {
        public string Name { get; set; }
        public string Version { get; set; }
    }
}

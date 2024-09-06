using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace Tecan.Tools.Sbom2GlobalIdentifier
{
    public class InformationExtractor
    {
        /// <summary>
        /// denotes the extensions that are to be removed from the assemblyName present in the <see cref="Record"/>
        /// </summary>
        private static readonly IEnumerable<string> RemoveFromComponentName = [".dll", ".exe"];

        /// <summary>
        /// denotes the string to be searched for in the assemblyName. if this string is found in the current component, then it is skipped and no lookup is conducted for it
        /// </summary>
        private Lazy<string> _stringToAvoid;

        /// <summary>
        /// flag that denotes if a string is to be avoided or not, is used primarily for output purposes in <see cref="AddAssemblies(BomData)"/>
        /// </summary>
        internal bool IsStringToBeAvoided { get; private set; }

        /// <summary>
        /// this is the getter for <see cref="_stringToAvoid"/>. If it has been initialized, simply return the value, else throw an <see cref="InvalidOperationException"/>
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        public string StringToAvoid => _stringToAvoid == null
                    ? throw new InvalidOperationException( $"The param _stringToAvoid has not been initialized yet" )
                    : _stringToAvoid.Value;

        /// <summary>
        /// only allow the lazy initilization of <see cref="_stringToAvoid"/> once. the param <param name="valueFactory"> is a delegate (lambda expression in this case)
        /// that doesnt take any params, but returns a value of type <see cref="string"/>
        /// </summary>
        /// <param name="valueFactory"></param>
        /// <exception cref="InvalidOperationException"></exception>
        public void InitializeStringToAvoid( Func<string> valueFactory )
        { 
            if( string.IsNullOrEmpty( _stringToAvoid?.Value ) )
            {
                _stringToAvoid = new Lazy<string>( valueFactory );
                IsStringToBeAvoided = true;
                return;
            }
            ConsoleOutput.WriteToConsole( $"INFO: StringToAvoid has already been initialized with {_stringToAvoid.Value} and will not be updated" );          
        }

        /// <summary>
        /// extracts information(name and version) from <see cref="BomData"/> object for the API query later on
        /// </summary>
        /// <param name="pathToJson"></param>
        public ICollection<Record> ExtractInfo( string pathToJson, ICollection<string> componentNames )
        {
            try
            {
                var jsonContent = File.ReadAllText( pathToJson );
                var bomData = JsonConvert.DeserializeObject<BomData>( jsonContent );

                if( bomData == null )
                {
                    ConsoleOutput.WriteToConsole( Constants.BOM_DATA_NULL, ConsoleColor.Red );
                    return new Collection<Record>();
                }
                componentNames.Add( bomData.MetaData?.Component?.Name );
                return AddAssemblies( bomData );
            }
            catch( Exception e ) when( e is JsonSerializationException or JsonReaderException )
            {
                ConsoleOutput.WriteToConsole( $"{Constants.FILE_FORMAT_NOT_SUPPORTED}" );
            }
            return [];
        }


        /// <summary>
        /// extract name and version of all the components in the json file provided.
        /// add only the external assemblies(internal assemblies are the assemblies that start with the word specified in <see cref="StringToAvoid"/>)
        /// </summary>
        private ICollection<Record> AddAssemblies( BomData bomData )
        {
            ICollection<Record> assemblyInformation = new Collection<Record>();
            try
            {
                foreach( var component in bomData?.Components )
                {
                    var name = component.Name;
                    var version = component.Version == "0.0" ? "-" : component.Version;

                    ExcludeInternalAssemblies( ref assemblyInformation, name, version );
                }

                //this is for output only
                if( IsStringToBeAvoided )
                {
                    var avoidedAssemblyCount = bomData.Components.Count() - assemblyInformation.Count;
                    ConsoleOutput.WriteToConsole( $"INFO: Excluded {avoidedAssemblyCount} assemblies that contained '{_stringToAvoid.Value}'" );
                }

                return assemblyInformation;
            }
            catch( Exception e ) when( e.InnerException != null )
            {
                ConsoleOutput.WriteToConsole( e.Message, ConsoleColor.Red );
                return [];
            }
        }

        /// <summary>
        /// basically avoids adding the assemblies from the SBOM file into <param name="assemblyInformation"/> that contain the string to be avoided
        /// </summary>
        /// <param name="assemblyInformation"></param>
        /// <param name="name"></param>
        /// <param name="version"></param>
        private void ExcludeInternalAssemblies( ref ICollection<Record> assemblyInformation, string name, string version )
        {
            foreach( var extension in RemoveFromComponentName )
            {
                name = name.ToLowerInvariant().Replace( extension, "", StringComparison.OrdinalIgnoreCase );
            }

            // if IsStringToBeAvoided is set to False OR if the name doesn't contain the string we want to filter out then only add the record to the collection
            // this means if IsStringToBeAvoided is set to True then only we will go past the || and if IsStringToBeAvoided is set to True that means _stringToAvoid
            // already had a value assigned in InitializeStringToAvoid so we wont get a null exception
            if( !IsStringToBeAvoided || !name.Contains( _stringToAvoid.Value, StringComparison.InvariantCultureIgnoreCase ) )
            {
                assemblyInformation.Add( new Record( name, version ) );
            }
        }

    }
}


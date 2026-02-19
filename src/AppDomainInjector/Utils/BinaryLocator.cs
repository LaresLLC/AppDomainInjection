using System;
using System.Collections.Generic;
using System.IO;

namespace AppDomainInjector.Utils
{
    /// <summary>
    /// Locates legitimate .NET binaries on the system for use as injection targets.
    /// </summary>
    public static class BinaryLocator
    {
        private static readonly string[] CommonNetBinaries = new[]
        {
            "powershell.exe",
            "msbuild.exe",
            "installutil.exe",
            "regsvcs.exe",
            "regasm.exe",
            "csc.exe",
            "vbc.exe",
            "jsc.exe",
            "aspnet_compiler.exe"
        };

        private static readonly string[] SearchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0"),
            Environment.ExpandEnvironmentVariables(@"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319"),
            Environment.ExpandEnvironmentVariables(@"%WINDIR%\Microsoft.NET\Framework\v4.0.30319"),
        };

        /// <summary>
        /// Finds all available .NET binaries on the system.
        /// </summary>
        public static Dictionary<string, string> FindAvailableTargets()
        {
            var targets = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var searchPath in SearchPaths)
            {
                if (!Directory.Exists(searchPath))
                    continue;

                foreach (var binary in CommonNetBinaries)
                {
                    var fullPath = Path.Combine(searchPath, binary);
                    if (File.Exists(fullPath) && !targets.ContainsKey(binary))
                    {
                        targets[binary] = fullPath;
                    }
                }
            }

            return targets;
        }

        /// <summary>
        /// Resolves a binary name to its full path.
        /// </summary>
        public static string ResolveBinaryPath(string binaryName)
        {
            // If already a full path
            if (Path.IsPathRooted(binaryName) && File.Exists(binaryName))
                return binaryName;

            var targets = FindAvailableTargets();

            if (targets.TryGetValue(binaryName, out var path))
                return path;

            // Try adding .exe extension
            var withExe = binaryName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? binaryName
                : binaryName + ".exe";

            if (targets.TryGetValue(withExe, out path))
                return path;

            return null;
        }

        /// <summary>
        /// Prints all available targets to console.
        /// </summary>
        public static void ListTargets()
        {
            var targets = FindAvailableTargets();

            Console.WriteLine("\n[*] Available .NET binary targets:\n");
            Console.WriteLine("    {0,-25} {1}", "Binary", "Path");
            Console.WriteLine("    {0,-25} {1}", new string('-', 20), new string('-', 50));

            foreach (var kvp in targets)
            {
                Console.WriteLine("    {0,-25} {1}", kvp.Key, kvp.Value);
            }

            Console.WriteLine();
        }
    }
}

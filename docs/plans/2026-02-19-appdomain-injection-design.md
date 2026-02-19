# AppDomain Injection POC - Design Document

## Overview

Purple Team tool to simulate AppDomain Injection techniques for detection validation. Implements two variants of the technique with benign payloads (calc.exe).

## Objective

Execute AppDomain Injection TTP against legitimate Microsoft .NET binaries to validate whether client defenses detect/block the technique.

## Techniques Implemented

### Technique 1: Config File Hijack

1. Copy legitimate .NET binary (e.g., `powershell.exe`) to controlled directory
2. Generate `.config` file pointing to malicious AppDomainManager
3. Place payload DLL in same directory
4. Execute binary - CLR loads payload automatically

**Artifacts:**
- Binary copy in temp directory
- `.config` file alongside binary
- Payload DLL

### Technique 2: Environment Variable Hijack

1. Place payload DLL in accessible directory
2. Set environment variables:
   - `APPDOMAIN_MANAGER_ASM` - Assembly full name
   - `APPDOMAIN_MANAGER_TYPE` - Type full name
   - `COMPLUS_Version` - CLR version
3. Execute target .NET process
4. CLR reads env vars and loads payload

**Artifacts:**
- Payload DLL
- Environment variables on process
- ETW events

## Architecture

```
AppDomainInjector/
├── src/
│   ├── AppDomainInjector/           # CLI tool
│   │   ├── Program.cs
│   │   ├── Techniques/
│   │   │   ├── ConfigHijack.cs
│   │   │   └── EnvVarHijack.cs
│   │   └── Utils/
│   │       ├── BinaryLocator.cs
│   │       └── ConfigGenerator.cs
│   └── Payload/
│       └── Injector.cs              # AppDomainManager payload
├── docs/
│   ├── TECHNIQUE.md
│   ├── DETECTION.md
│   └── MITRE_MAPPING.md
└── README.md
```

## CLI Interface

```bash
# Config hijack
AppDomainInjector.exe --technique config --target powershell.exe

# Environment variable hijack
AppDomainInjector.exe --technique env --target msbuild.exe

# List available .NET targets
AppDomainInjector.exe --list-targets
```

## Payload

```csharp
public class Injector : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        Process.Start("calc.exe");
        base.InitializeNewDomain(appDomainInfo);
    }
}
```

## MITRE ATT&CK Mapping

- **T1055** - Process Injection
- **T1574.001** - Hijack Execution Flow: DLL Search Order Hijacking
- **T1059.001** - Command and Scripting Interpreter: PowerShell

## Detection Opportunities

| Technique | Detection Method |
|-----------|------------------|
| Config Hijack | Sysmon Event 11 (FileCreate), config files near MS binaries |
| Env Var Hijack | Process creation with APPDOMAIN_MANAGER_* env vars |
| Both | ETW Microsoft-Windows-DotNETRuntime, unsigned DLL loads |

## Language & Framework

- C# / .NET Framework 4.7.2
- Compatible with Windows 10/11 default .NET installation

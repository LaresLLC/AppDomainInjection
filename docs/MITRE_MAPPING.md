# MITRE ATT&CK Mapping

## Overview

This tool simulates AppDomain Injection techniques mapped to the MITRE ATT&CK framework.

## Techniques

### T1055 - Process Injection

**Tactic:** Defense Evasion, Privilege Escalation

**Description:** Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.

**Implementation in this tool:**
- Environment Variable Hijack injects code into a target .NET process by manipulating CLR initialization
- The payload executes within the context of a legitimate Microsoft-signed process

**Reference:** https://attack.mitre.org/techniques/T1055/

---

### T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking

**Tactic:** Persistence, Privilege Escalation, Defense Evasion

**Description:** Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs.

**Implementation in this tool:**
- Config File Hijack places a `.config` file alongside a copied Microsoft binary
- The CLR loads the malicious AppDomainManager DLL as specified in the config
- The legitimate binary's execution flow is hijacked to load attacker code

**Reference:** https://attack.mitre.org/techniques/T1574/001/

---

### T1059.001 - Command and Scripting Interpreter: PowerShell

**Tactic:** Execution

**Description:** Adversaries may abuse PowerShell commands and scripts for execution.

**Implementation in this tool:**
- PowerShell.exe is a common target for AppDomain Injection
- The injected AppDomainManager executes before PowerShell scripts run
- Allows execution of arbitrary code under the guise of PowerShell

**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Detection Opportunities

### For Config File Hijack (T1574.001)

| Detection Method | Data Source | Description |
|------------------|-------------|-------------|
| File Monitoring | Sysmon Event 11 | `.config` files created near Microsoft binaries |
| File Monitoring | Sysmon Event 11 | Unsigned DLLs in Windows directories |
| Module Load | Sysmon Event 7 | Unsigned DLLs loaded by signed Microsoft processes |
| Process Monitoring | Sysmon Event 1 | Microsoft binaries executed from unusual paths |

**Sigma Rule Concept:**
```yaml
title: Suspicious .config File Creation
status: experimental
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '.exe.config'
        TargetFilename|contains:
            - '\Temp\'
            - '\AppData\'
    condition: selection
```

### For Environment Variable Hijack (T1055)

| Detection Method | Data Source | Description |
|------------------|-------------|-------------|
| Process Monitoring | Sysmon Event 1 | Processes with APPDOMAIN_MANAGER_* env vars |
| ETW Tracing | Microsoft-Windows-DotNETRuntime | AppDomainManager load events |
| Module Load | Sysmon Event 7 | Unsigned assemblies loaded via AppDomainManager |

**Sigma Rule Concept:**
```yaml
title: AppDomainManager Injection via Environment Variables
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'APPDOMAIN_MANAGER_ASM'
            - 'APPDOMAIN_MANAGER_TYPE'
    filter:
        # Legitimate uses - adjust as needed
        ParentImage|endswith: '\devenv.exe'
    condition: selection and not filter
```

## Procedure Examples

### Real-World Usage

This technique has been observed in:

1. **Cobalt Strike** - Uses AppDomainManager injection for execute-assembly
2. **Red Team Operations** - Commonly used for .NET assembly execution in memory
3. **APT Groups** - Various threat actors have used similar techniques

### Test Procedure

```bash
# 1. Build the tool
dotnet build AppDomainInjector.sln

# 2. Execute Config Hijack against PowerShell
AppDomainInjector.exe --technique config --target powershell.exe --iocs

# 3. Execute Environment Variable Hijack against MSBuild
AppDomainInjector.exe --technique env --target msbuild.exe --iocs

# 4. Verify detection in SIEM/EDR
# Check for:
# - Sysmon Event 11 (FileCreate) for .config files
# - Sysmon Event 7 (ImageLoad) for Payload.dll
# - Sysmon Event 1 (ProcessCreate) with suspicious env vars
```

## References

- [MITRE ATT&CK - T1055](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK - T1574.001](https://attack.mitre.org/techniques/T1574/001/)
- [MITRE ATT&CK - T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft Docs - AppDomainManager](https://docs.microsoft.com/en-us/dotnet/api/system.appdomainmanager)
- [TheWover - AppDomain Manager Injection](https://thewover.github.io/Introducing-Donut/)

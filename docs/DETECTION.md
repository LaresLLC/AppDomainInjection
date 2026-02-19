# Detection Guide - Blue Team

## Overview

This document provides guidance for detecting AppDomain Injection techniques. Use this during Purple Team exercises to validate your detection capabilities.

## Indicators of Compromise (IOCs)

### Config File Hijack

#### File-Based IOCs

| Indicator | Description |
|-----------|-------------|
| `*.exe.config` in temp directories | Config files shouldn't exist in %TEMP% |
| Unsigned DLLs near Microsoft binaries | Legitimate MS binaries don't ship with third-party DLLs |
| Microsoft binaries in unusual locations | powershell.exe in %TEMP% is suspicious |

#### Process-Based IOCs

| Indicator | Description |
|-----------|-------------|
| MS binary executing from %TEMP% | Legitimate execution is from System32/SysWOW64 |
| MS binary loading unsigned DLLs | Check ImageLoad events for unsigned modules |
| Child process spawned unexpectedly | calc.exe from powershell.exe in %TEMP% |

### Environment Variable Hijack

#### Environment IOCs

| Variable | Suspicion Level |
|----------|-----------------|
| `APPDOMAIN_MANAGER_ASM` | HIGH - Rarely used legitimately |
| `APPDOMAIN_MANAGER_TYPE` | HIGH - Rarely used legitimately |
| `COMPLUS_Version` | MEDIUM - Has legitimate uses |

#### Process IOCs

| Indicator | Description |
|-----------|-------------|
| Process with APPDOMAIN_MANAGER_* | Capture env vars on process creation |
| Unexpected DLL loads in .NET processes | Monitor ImageLoad events |
| ETW events for AppDomainManager | Microsoft-Windows-DotNETRuntime provider |

## Detection Rules

### Sysmon Configuration

Add these to your Sysmon config:

```xml
<!-- File Create: Config files in suspicious locations -->
<FileCreate onmatch="include">
    <TargetFilename condition="end with">.exe.config</TargetFilename>
    <TargetFilename condition="contains">\Temp\</TargetFilename>
    <TargetFilename condition="contains">\AppData\</TargetFilename>
</FileCreate>

<!-- Image Load: Unsigned DLLs loaded by signed MS binaries -->
<ImageLoad onmatch="include">
    <Signed condition="is">false</Signed>
</ImageLoad>

<!-- Process Create: Capture environment variables -->
<ProcessCreate onmatch="include">
    <Image condition="end with">powershell.exe</Image>
    <Image condition="end with">msbuild.exe</Image>
</ProcessCreate>
```

### Sigma Rules

#### Config File Hijack Detection

```yaml
title: AppDomainManager Config File Hijack
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects creation of .exe.config files in suspicious locations
author: Purple Team
references:
    - https://attack.mitre.org/techniques/T1574/001/
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '.exe.config'
    filter_legitimate_paths:
        TargetFilename|startswith:
            - 'C:\Program Files'
            - 'C:\Windows\Microsoft.NET'
    condition: selection and not filter_legitimate_paths
level: high
tags:
    - attack.defense_evasion
    - attack.t1574.001
```

#### Environment Variable Hijack Detection

```yaml
title: AppDomainManager Injection via Environment Variables
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: Detects processes started with AppDomainManager environment variables
author: Purple Team
references:
    - https://attack.mitre.org/techniques/T1055/
logsource:
    product: windows
    category: process_creation
detection:
    selection_env:
        ParentCommandLine|contains:
            - 'APPDOMAIN_MANAGER_ASM'
            - 'APPDOMAIN_MANAGER_TYPE'
    condition: selection_env
level: high
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
```

#### Microsoft Binary in Suspicious Location

```yaml
title: Microsoft Binary Executed from Suspicious Location
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: Detects Microsoft-signed binaries running from temp directories
author: Purple Team
logsource:
    product: windows
    category: process_creation
detection:
    selection_binary:
        Image|endswith:
            - '\powershell.exe'
            - '\msbuild.exe'
            - '\csc.exe'
            - '\installutil.exe'
    selection_path:
        Image|contains:
            - '\Temp\'
            - '\AppData\Local\Temp\'
    condition: selection_binary and selection_path
level: high
tags:
    - attack.defense_evasion
    - attack.t1574.001
```

## ETW Detection

### Microsoft-Windows-DotNETRuntime Provider

Enable this ETW provider to monitor .NET runtime events:

```powershell
# Start ETW trace
logman create trace DotNetTrace -p Microsoft-Windows-DotNETRuntime 0x8000 -o dotnet.etl

# Stop and analyze
logman stop DotNetTrace
```

Key events to monitor:
- **AppDomainLoad** - New AppDomain created
- **AssemblyLoad** - Assembly loaded into process
- **ModuleLoad** - Module loaded

## Testing Your Detections

### Pre-Test Checklist

- [ ] Sysmon installed and configured
- [ ] Log forwarding to SIEM active
- [ ] Detection rules deployed
- [ ] Alert channels configured

### Test Procedure

1. **Baseline:** Note current alert count
2. **Execute Config Hijack:**
   ```cmd
   AppDomainInjector.exe --technique config --target powershell.exe --iocs
   ```
3. **Verify Detections:**
   - Check for Sysmon Event 11 (FileCreate)
   - Check for Sysmon Event 7 (ImageLoad)
   - Check for Sysmon Event 1 (ProcessCreate)
4. **Execute Env Var Hijack:**
   ```cmd
   AppDomainInjector.exe --technique env --target powershell.exe --iocs
   ```
5. **Verify Detections:**
   - Check for process with suspicious env vars
   - Check for ETW events
6. **Document Results:** Note which detections fired/missed

### Expected Results

| Technique | Expected Alerts |
|-----------|-----------------|
| Config Hijack | File creation, unsigned DLL load, unusual process location |
| Env Var Hijack | Process with env vars (if captured), ETW events |

## Gaps and Recommendations

### Common Detection Gaps

1. **Environment Variables Not Captured**
   - Solution: Enable Sysmon with command line logging
   - Solution: Use EDR that captures process environment

2. **Unsigned DLL Loads Not Monitored**
   - Solution: Enable Sysmon ImageLoad events
   - Solution: Implement application whitelisting

3. **ETW Not Collected**
   - Solution: Enable .NET runtime ETW provider
   - Solution: Forward to SIEM for analysis

### Hardening Recommendations

1. **Application Whitelisting:** Block execution from %TEMP%
2. **Code Signing:** Require signed assemblies via policy
3. **Constrained Language Mode:** Limit PowerShell capabilities
4. **AMSI Integration:** Ensure AMSI scans loaded assemblies

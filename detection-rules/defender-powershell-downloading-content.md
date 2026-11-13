# PowerShell downloading content

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceProcessEvents` (PowerShell process creation and command-line telemetry).

**Objective:** Identify PowerShell command lines containing methods and cmdlets commonly used to retrieve remote content.

## KQL hunting query

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Invoke-WebRequest",
    "Invoke-RestMethod",
    "DownloadFile",
    "DownloadString",
    "DownloadData",
    "WebClient",
    "iwr",
    "irm"
)
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

## What the query does

The query filters PowerShell processes for selected web retrieval keywords. Cmdlets such as `Invoke-WebRequest` and `Invoke-RestMethod` are used for HTTP requests, while `DownloadFile`, `DownloadString` and `DownloadData` can indicate .NET WebClient usage. `iwr` and `irm` are common aliases.

## Example

A PowerShell command contains `Invoke-WebRequest -Uri 'https://example.com/file.txt' -OutFile 'C:\Temp\file.txt'`. This is an illustrative command line using a documentation domain.

## Investigation pivots

- Identify the URL, requested content, destination file and parent process.
- Review script-block logging (PowerShell Operational 4104) if available, including decoded or indirectly invoked script content.
- Correlate with DeviceNetworkEvents and DeviceFileEvents to determine whether content was retrieved and subsequently executed.

**False positives:** Software deployment, updates, administration, legitimate API integrations and automation.

**Limitations:** This is command-line keyword matching, not proof of successful download. It may match text that is not executed, and may miss encoded, obfuscated, indirect or script-file-based retrieval. Network and file evidence can help establish the outcome.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) · [PowerShell investigation playbook](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/playbooks/suspicious-powershell.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

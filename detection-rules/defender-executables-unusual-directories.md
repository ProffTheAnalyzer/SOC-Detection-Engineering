# Executables from unusual directories

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceProcessEvents` (onboarded Windows endpoints and process telemetry).

**Objective:** Identify executable files launched from common download, temporary and staging directories that may warrant investigation.

## KQL hunting query

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName endswith ".exe"
| where FolderPath contains @"\Downloads\"
    or FolderPath contains @"\AppData\Local\Temp\"
    or FolderPath contains @"\Users\Public\"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, SHA1
| order by Timestamp desc
```

## What the query does

The query looks for `.exe` process creation events where the recorded path contains one of three selected directory patterns. It returns the executable, path, initiating process, account, command line and SHA1 to support triage.

## Example

An unfamiliar `update.exe` runs from `C:\Users\Public\update.exe`. Investigate whether it is a legitimate installer or an unexpected payload.

## Investigation pivots

- Review the file's origin, download history, hash and digital signature using endpoint telemetry and approved reputation tools.
- Inspect the parent process, command line, user and device role. Check whether the executable was launched from a document, browser or script.
- Correlate network connections, file and registry changes, and subsequent process execution.

**False positives:** Approved installers, legitimate downloads, temporary installation executables and portable applications.

**Limitations:** A user-writable directory is not inherently malicious. This hunt covers selected Windows paths and `.exe` filenames only; it does not capture all staging paths, scripts, DLLs or renamed files. It detects process creation, not every downloaded file.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) · [Windows process behavior](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/analysis/windows-process-baselines.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

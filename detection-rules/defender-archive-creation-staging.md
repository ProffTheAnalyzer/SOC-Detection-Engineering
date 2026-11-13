# Archive creation and potential data staging

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceFileEvents` (endpoint file creation, modification and rename telemetry).

**Objective:** Identify newly created, modified or renamed archive files that may represent data collection or staging before a potential transfer.

## KQL hunting query

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in~ ("FileCreated", "FileModified", "FileRenamed")
| where FileName endswith ".zip"
    or FileName endswith ".7z"
    or FileName endswith ".rar"
    or FileName endswith ".tar"
    or FileName endswith ".gz"
| project Timestamp, DeviceId, DeviceName, ActionType,
          FileName, FolderPath, FileSize, SHA1,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

## What the query does

This query finds file activity for selected archive extensions, regardless of whether the archive was created through Explorer, PowerShell, 7-Zip, WinRAR or another program. Review FileSize in bytes and the originating process. An optional size threshold such as `| where FileSize >= 50 * 1024 * 1024` can prioritize archives of at least 50 MiB when size is populated, but can miss smaller archives and files still being written. Archive creation, modification and rename events can describe the same file more than once.

## Example

An unfamiliar process creates a large ZIP file in a temporary directory after accessing several business document folders. Shortly afterward, network activity is observed. This is a hypothetical staging scenario requiring evidence of the actual file contents and transfer.

## Investigation pivots

- Identify the archive path, size, hash, user, creator and source files, where available. Establish whether the archive contains sensitive material using authorized inspection and data-classification evidence.
- Review preceding file access, discovery and archive-tool process events. Distinguish newly assembled archives from routine downloads or copied archives.
- Correlate subsequent network, proxy, DLP, cloud-storage and file-transfer evidence to determine whether the archive was actually uploaded, copied or exfiltrated. Match relevant file identity and timestamps rather than assuming any later connection carried the archive.

**False positives:** Backups, log collection, application packages, legitimate document sharing, software development and ordinary downloads.

**Limitations:** Compression alone is not evidence of exfiltration. Extension matching misses disguised or extensionless archives and does not establish archive contents or encryption. FileSize can be incomplete or unavailable. Network connection events alone do not provide proof that an archive was transferred or the number of bytes exfiltrated; use appropriate transfer or application telemetry.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) · [SOC network and ransomware behavior](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/analysis/network-email-and-ransomware.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

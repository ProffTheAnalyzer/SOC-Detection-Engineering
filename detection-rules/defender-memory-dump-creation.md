# Memory dump file creation, including Task Manager

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceFileEvents` (endpoint file creation, modification and rename telemetry).

**Objective:** Find memory dump artifacts and identify the process and account associated with their creation or modification, including GUI-based dumping through Task Manager.

## KQL hunting query

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in~ ("FileCreated", "FileModified", "FileRenamed")
| where FileName endswith ".dmp"
    or FileName endswith ".mdmp"
| project Timestamp, DeviceId, DeviceName, ActionType,
          FileName, FolderPath, FileSize, SHA1,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

## What the query does

The query starts from the dump file rather than a particular command-line tool. It can surface files written by Task Manager (taskmgr.exe), ProcDump or another process if the corresponding file activity is recorded. Task Manager can create a process memory dump through its GUI without launching a separate dump-specific command line. Review the recorded initiating process; it is not necessarily the original requester or the process whose memory was captured. FileSize is in bytes and may be missing or incomplete while a dump is being written.

## Example

A file named `lsass.dmp` appears in a user's temporary directory, with `taskmgr.exe` recorded as the initiating process. This is a hypothetical high-priority investigation lead, not proof that LSASS memory was successfully acquired or credentials recovered.

## Investigation pivots

- Identify the exact file path, hash, size, timestamps, creating process and account. Determine whether the file is a real memory dump and which process or system memory it represents using approved forensic tooling.
- Review related process activity, Task Manager or debugging context, user privileges and any Defender prevention or credential-protection events. Sysmon Event 10 can provide additional process-access context if configured.
- Check subsequent file access, archive creation, movement, deletion or transfer. Treat memory dumps as potentially sensitive; do not upload them to public analysis services.

**False positives:** Application crash dumps, troubleshooting, approved debugging, Windows Error Reporting and authorized diagnostic collection.

**Limitations:** Filename extensions are only a heuristic. Renamed or extensionless dumps, memory-only collection, blocked dumping and file actions not captured by the sensor can be missed. A dump of an ordinary application is different from an LSASS dump, and a filename alone cannot identify the memory contents. Task Manager may be legitimate and Windows protections can prevent access to protected processes.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) · [Sysmon event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) · [SOC authentication and credentials reference](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/notes/SOC_Master_Notebook_Clean.md#03-windows-authentication-credentials-and-active-directory)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

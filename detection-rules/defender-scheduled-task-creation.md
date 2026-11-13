# Scheduled task creation

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceProcessEvents` (Windows process and command-line telemetry).

**Objective:** Identify attempts to create scheduled tasks with `schtasks.exe` for investigation of persistence or administrative activity.

## KQL hunting query

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

## What the query does

The query matches `schtasks.exe` processes whose command line contains `/create`, which is the task creation operation. It captures the attempting process and parent context, not necessarily a successfully registered task.

## Example

An unfamiliar process creates a task intended to launch a script at user logon.

## Investigation pivots

- Identify the task name, action, arguments, trigger, configured run-as account and privileges.
- Inspect the initiating process and the origin, signature and hash of the configured payload.
- Confirm task registration using Security Event 4698 when audited, Task Scheduler logs or task configuration. Review actual execution and subsequent activity.

**False positives:** Endpoint management, installers, software updaters, backup agents and scheduled IT maintenance.

**Limitations:** This covers only the `schtasks.exe /create` pattern. Tasks created through PowerShell, COM, APIs or other tools may not appear. A matching command does not establish successful registration, execution or malicious persistence.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) · [Windows Event 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698) · [Persistence investigation playbook](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/playbooks/suspicious-persistence.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

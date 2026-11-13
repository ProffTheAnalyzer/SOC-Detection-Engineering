# Windows service creation using sc.exe

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceProcessEvents` (Windows process and command-line telemetry).

**Objective:** Identify attempts to create Windows services through `sc.exe`, which may be relevant to persistence, privileged execution or remote administration.

## KQL hunting query

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has "create"
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

## What the query does

The query looks for instances of `sc.exe` with the `create` term in the command line. Review the full arguments to determine the requested service operation, target and configuration.

## Example

An administrative session attempts to create a service configured to run an unfamiliar executable from a user-writable path.

## Investigation pivots

- Identify the service name, binary path, arguments, account, start type and whether a remote target was specified.
- Review the initiating process, account, file origin, hash, signer and associated authentication or remote management activity.
- Correlate with System Event 7045 or Security Event 4697 (where audited) to confirm installation. Check the destination host and whether the service actually started.

**False positives:** Software installation, security agents, deployment tools and routine service administration.

**Limitations:** A matching command is not proof of service installation or execution. This keyword-based query can match unrelated uses of the word create and does not cover services installed through other APIs or tools.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) · [Windows Event 4697](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697) · [SOC telemetry matrix](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/references/event-telemetry-matrix.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

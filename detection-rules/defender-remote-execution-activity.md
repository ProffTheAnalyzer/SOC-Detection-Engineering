# Remote execution activity

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceProcessEvents` (Windows process creation and initiating-process telemetry).

**Objective:** Identify destination-side process activity consistent with remote execution through common Windows administration mechanisms.

## KQL hunting query

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "wmiprvse.exe", "wsmprovhost.exe", "psexesvc.exe"
)
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "rundll32.exe"
)
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## What the query does

The hunt identifies selected shells and interpreters launched by WMI Provider Host, Windows PowerShell remoting host or the default PsExec service executable. These relationships are useful destination-side investigative leads, but WMI and remoting-related process names do not establish that a request came from another machine. A remote operation may also execute code inside a host process without spawning one of these child processes.

## Example

A server's `wmiprvse.exe` launches `cmd.exe` shortly after an unfamiliar administrator authenticates from another workstation. Investigate whether it was an authorized management operation or possible lateral execution.

## Investigation pivots

- Confirm exact process lineage, command, device, account, privileges, timestamps and the resulting actions.
- Review DeviceLogonEvents and Windows Security 4624/4648 where collected; establish the source system and whether the authentication and execution are related. Correlate WMI/WinRM logs, SMB activity and service creation (System 7045 or Security 4697) as applicable.
- Check authorization, remote-management infrastructure and similar activity on other hosts. Follow resulting files, network connections, services and scheduled tasks.

**False positives:** Remote support, system administrators, software deployment, inventory, monitoring and approved management automation.

**Limitations:** The selected parent/child patterns capture only a subset of remote execution. Custom service names, other tools, local WMI activity, in-process PowerShell remoting and direct execution of other binaries may be missed. A matching relationship does not establish lateral movement, successful authentication from a remote system or malicious intent.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) · [DeviceLogonEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) · [SOC remote administration reference](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/notes/SOC_Master_Notebook_Clean.md#04-remote-administration-and-lateral-movement)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

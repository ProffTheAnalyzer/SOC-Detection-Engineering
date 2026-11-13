# System and account discovery commands

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceProcessEvents` (Windows process creation and command-line telemetry).

**Objective:** Identify common discovery commands that reveal a host's configuration, identities, network, running processes or domain relationships.

## KQL hunting query

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "whoami.exe", "systeminfo.exe", "hostname.exe",
    "ipconfig.exe", "netstat.exe", "arp.exe",
    "tasklist.exe", "nltest.exe", "quser.exe", "qwinsta.exe"
)
    or (FileName in~ ("net.exe", "net1.exe")
        and ProcessCommandLine has_any (
            "user", "group", "localgroup", "view", "share"
        ))
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

## What the query does

The query finds selected Windows utilities and filters net.exe/net1.exe for common account, group and share-related terms. `whoami` identifies the current account; `systeminfo` reports operating system and host information; `ipconfig` shows network configuration; `nltest` can query domain information. Review exact arguments: some net commands modify rather than merely enumerate accounts, groups or shares.

## Example

An unfamiliar process launches `whoami.exe`, `systeminfo.exe`, `ipconfig.exe` and `net.exe` within a short period. The cluster is worth investigating in the context of the parent process and user.

## Investigation pivots

- Establish the parent process, user, command-line arguments and device role. Distinguish a help-desk session from an unexpected script or payload.
- Look for multiple discovery commands in a short time window and correlate related process instances on the same device.
- Review preceding execution, network activity, authentication, account changes and subsequent remote access. Determine whether a command attempted enumeration or actually returned useful information.

**False positives:** IT troubleshooting, inventory agents, login scripts, endpoint management and authorized security assessments.

**Limitations:** Discovery commands are common legitimate operations. This hunt does not cover every discovery method, PowerShell cmdlets, built-in shell commands or API-based enumeration. A matching process is not proof of malicious discovery or successful enumeration.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) · [SOC command-line investigation library](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/notes/SOC_Master_Notebook_Clean.md#14-command-line-detection-and-investigation-library)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

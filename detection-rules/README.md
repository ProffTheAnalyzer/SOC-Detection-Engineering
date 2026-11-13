# Detection and hunting queries

These KQL examples explore security behavior using Microsoft Sentinel and Microsoft Defender XDR advanced hunting.

| Query | Platform | What it looks for |
|---|---|---|
| [Unfamiliar sign-in IP](entra-unfamiliar-ip-signins.md) | Sentinel / Log Analytics | User and IP combinations first seen within a recent time window |
| [Encoded PowerShell command](defender-powershell-encoded-command.md) | Defender XDR | PowerShell processes using encoded-command arguments |
| [Suspicious email URL clicks](defender-email-url-clicks.md) | Defender XDR | URL clicks correlated with email delivery |
| [Office launches a script interpreter](defender-office-launching-script-interpreter.md) | Defender XDR | Direct Office-to-interpreter process relationships |
| [IIS worker launches a shell](defender-iis-worker-shell.md) | Defender XDR | Web application worker starting a shell or interpreter |
| [Run/RunOnce registry edits](defender-run-key-changes.md) | Defender XDR | Changes to persistence-capable registry values |
| [Executables from unusual directories](defender-executables-unusual-directories.md) | Defender XDR | Executables launched from Downloads, Temp or Public directories |
| [PowerShell downloading content](defender-powershell-downloading-content.md) | Defender XDR | PowerShell commands containing web retrieval methods or aliases |
| [Scheduled task creation](defender-scheduled-task-creation.md) | Defender XDR | schtasks.exe command-line task creation attempts |
| [Windows service creation using sc.exe](defender-windows-service-creation.md) | Defender XDR | sc.exe command-line service creation attempts |
| [Potential password spraying](entra-potential-password-spraying.md) | Sentinel / Log Analytics | Invalid credential attempts against multiple users from one IP |
| [Outbound RDP activity to multiple destinations](defender-outbound-rdp-multiple-destinations.md) | Defender XDR | Successful outbound connections to multiple public IPs on port 3389 |
| [System and account discovery commands](defender-system-account-discovery.md) | Defender XDR | Common Windows discovery utilities and account enumeration commands |
| [Memory dump file creation, including Task Manager](defender-memory-dump-creation.md) | Defender XDR | Dump artifacts and their initiating processes, including Task Manager |
| [Remote execution activity](defender-remote-execution-activity.md) | Defender XDR | Shells and interpreters spawned by WMI, WinRM or PsExec-related processes |
| [Remote authentication across multiple endpoints](defender-remote-logons-multiple-endpoints.md) | Defender XDR | Successful network or remote interactive logons to multiple devices |
| [Archive creation and potential data staging](defender-archive-creation-staging.md) | Defender XDR | ZIP, 7z, RAR and other archives written or renamed on endpoints |
| [Potential ransom note creation](defender-potential-ransom-note-creation.md) | Defender XDR | File creation or rename with common ransom-note naming patterns |

## Using the queries

Confirm the data source, time range and required fields before running a query. A hunting result is an investigative lead, not automatic evidence of compromise. Consider legitimate behavior and corroborating telemetry before determining the outcome.

The examples in this section have not been validated in a tenant. They are intended for learning and investigation rather than direct production deployment.

[Back to repository home](../README.md)

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

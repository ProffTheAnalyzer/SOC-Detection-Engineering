# Detection Engineering

My practical collection of **Microsoft Sentinel KQL and Microsoft Defender XDR advanced hunting queries**, with investigation examples and explanations of suspicious security activity.

I document queries, investigative approaches and lessons learned as I develop my skills through hands-on practice and cybersecurity investigations. This collection serves as my personal reference and a resource for others exploring detection engineering and SOC analysis.

I may expand and update the material as I see fit.

## Explore the repository

| Section | Contents |
|---|---|
| [Detection and hunting queries](detection-rules/README.md) | KQL examples for endpoint, identity and email investigations |
| [Investigation walkthroughs](investigation-walkthroughs/README.md) | Interpreting security telemetry, evaluating suspicious behavior and practicing investigative decisions |

## Hunting queries

| Query | Platform |
|---|---|
| [Successful Entra sign-ins from an unfamiliar IP](detection-rules/entra-unfamiliar-ip-signins.md) | Microsoft Sentinel |
| [Encoded PowerShell execution](detection-rules/defender-powershell-encoded-command.md) | Microsoft Defender XDR |
| [Suspicious email URL clicks](detection-rules/defender-email-url-clicks.md) | Microsoft Defender XDR |
| [Office launches a script interpreter](detection-rules/defender-office-launching-script-interpreter.md) | Microsoft Defender XDR |
| [IIS worker launches a shell](detection-rules/defender-iis-worker-shell.md) | Microsoft Defender XDR |
| [Registry Run/RunOnce changes](detection-rules/defender-run-key-changes.md) | Microsoft Defender XDR |
| [Executables from unusual directories](detection-rules/defender-executables-unusual-directories.md) | Microsoft Defender XDR |
| [PowerShell downloading content](detection-rules/defender-powershell-downloading-content.md) | Microsoft Defender XDR |
| [Scheduled task creation](detection-rules/defender-scheduled-task-creation.md) | Microsoft Defender XDR |
| [Windows service creation using sc.exe](detection-rules/defender-windows-service-creation.md) | Microsoft Defender XDR |
| [Potential password spraying](detection-rules/entra-potential-password-spraying.md) | Microsoft Sentinel |
| [Outbound RDP activity to multiple destinations](detection-rules/defender-outbound-rdp-multiple-destinations.md) | Microsoft Defender XDR |
| [System and account discovery commands](detection-rules/defender-system-account-discovery.md) | Microsoft Defender XDR |
| [Memory dump file creation, including Task Manager](detection-rules/defender-memory-dump-creation.md) | Microsoft Defender XDR |
| [Remote execution activity](detection-rules/defender-remote-execution-activity.md) | Microsoft Defender XDR |
| [Remote authentication across multiple endpoints](detection-rules/defender-remote-logons-multiple-endpoints.md) | Microsoft Defender XDR |
| [Archive creation and potential data staging](detection-rules/defender-archive-creation-staging.md) | Microsoft Defender XDR |
| [Potential ransom note creation](detection-rules/defender-potential-ransom-note-creation.md) | Microsoft Defender XDR |

These are hunting and investigation examples, not deployed production rules. Verify table availability, required telemetry and the meaning of query results in your environment. Individual pages describe the query's scope and limitations.

## Investigation walkthroughs

- [NTLM, Kerberos and Active Directory replication](investigation-walkthroughs/identity-attack-signals.md)
- [Normal vs. suspicious detection decisions](investigation-walkthroughs/normal-vs-suspicious-detection-decisions.md)
- [SOC investigation practice cases](investigation-walkthroughs/practice-cases.md)
- [MITRE ATT&CK technique mapping](investigation-walkthroughs/mitre-technique-mapping.md)

## Related projects

- [SOC Knowledge Base](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base) — cybersecurity concepts, investigation playbooks and telemetry references.
- [SOC Lab](https://github.com/ProffTheAnalyzer/Ebenezer-SOC-Lab) — hands-on security platform setup, logging, detections and automation.

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

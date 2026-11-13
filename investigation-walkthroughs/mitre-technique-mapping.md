# MITRE ATT&CK mapping — context over label

> **Purpose:** Add technique mapping to a documented observed behavior, rather than attach an attack label to every event.

| Observable behavior | Potential ATT&CK technique | What the mapping means |
|---|---|---|
| PowerShell used to execute a script | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — PowerShell | Execution mechanism; not proof malicious |
| New scheduled task used to persist | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) — Scheduled Task | Only relevant when linked to the attack/persistence behavior |
| Startup Run key used for persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) — Registry Run Keys / Startup Folder | Requires evidence of persistence mechanism |
| SMB shares used for lateral movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) — SMB/Windows Admin Shares | Normal SMB traffic alone does not imply movement |
| Valid credentials abused for access | [T1078](https://attack.mitre.org/techniques/T1078/) — Valid Accounts | You must establish misuse, not merely successful logon |
| Replication abuse to obtain credentials | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) — DCSync | Requires evidence of abuse of replication operations |

## Method

1. Define the observed technical action and data source.
2. Identify its behavioral purpose (execution, persistence, credential access, lateral movement).
3. Check official technique description and platforms.
4. Record certainty: supported by logs, plausible hypothesis, or not proven.
5. Include telemetry prerequisites and benign lookalikes.

Source: [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/).

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

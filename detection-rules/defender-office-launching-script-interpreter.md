# Office application launches a script interpreter

> **Validation:** Hunting example; not tenant-tested. **Platform:** Microsoft Defender XDR advanced hunting. **Goal:** Surface unusual Office-to-shell parent/child relationships.

## Query

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, Child = FileName,
          ProcessCommandLine, InitiatingProcessCommandLine,
          FolderPath, SHA1, ProcessUniqueId, InitiatingProcessUniqueId
| order by Timestamp desc
```

## Normal vs suspicious

- **Possible benign:** Enterprise macros/integration, accessibility tooling, automation, sanctioned admin documents.
- **Greater concern:** Attachment/phishing origin, encoded/download commands, unsigned payload, unexpected network calls, new scheduled task or sensitive-file access.

## Investigation

1. Validate the exact process and parent instance using unique IDs where populated.
2. Inspect command text and document/mail source; review endpoint alert and download history.
3. Correlate network/file/registry activity and compare to approved Office workflows.
4. Determine whether it represents an isolated legitimate event or part of a suspicious chain.

**Limitations:** The query covers this *immediate* parent-child pattern, not indirect execution through a broker/other process. It doesn't prove macro execution or exploitation. Older endpoints or incomplete onboarding can lack unique IDs.

## Test / ATT&CK

Execute a safe, approved Office automation example in a lab and verify expected result; check typical enterprise false positives. Potential [T1059](https://attack.mitre.org/techniques/T1059/) scripting only when supported by behavior.

[DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table).

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

# Potential ransom note creation

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceFileEvents` (endpoint file activity telemetry).

**Objective:** Identify newly created or renamed text and HTML-like files whose names contain common ransom-note terms, for early investigation of possible ransomware impact.

## KQL hunting query

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in~ ("FileCreated", "FileRenamed")
| where FileName endswith ".txt"
    or FileName endswith ".html"
    or FileName endswith ".htm"
    or FileName endswith ".hta"
| where FileName contains "decrypt"
    or FileName contains "ransom"
    or FileName contains "recover"
    or FileName contains "restore"
    or FileName contains "readme"
| project Timestamp, DeviceId, DeviceName, ActionType,
          FileName, FolderPath, SHA1,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

## What the query does

This hunt uses common naming terms to locate candidate ransom notes. The terms are deliberately broad to support investigation rather than act as a definitive ransomware signature. Review actual names, paths, file contents and creation context. A normal README or recovery guide can match; a note with a random name or different extension might not.

## Example

The same unfamiliar executable creates `README_TO_DECRYPT.txt` in several directories shortly after many documents are renamed. This illustrative combination warrants urgent investigation of possible ransomware impact.

## Investigation pivots

- Identify the creator, full path, hash, account and time. Safely inspect the note as data without following payment links, opening executable HTML applications or executing embedded content.
- Search for repeated note creation across directories and hosts, unusual file renames, extension changes, inaccessible documents, shadow-copy or backup changes and defense impairment.
- Determine whether unauthorized encryption or other destructive activity is occurring. Scope affected shares and devices, preserve evidence and escalate promptly under the incident-response process when active impact is indicated.

**False positives:** Legitimate README files, recovery instructions, software packages, restore utilities, security simulations and training material.

**Limitations:** Filename matching cannot establish note contents, encryption, extortion or family attribution. Ransomware may use unrelated names, other extensions, graphical messages or no note. The hunt covers selected creation and rename events only; absence of a match does not rule out ransomware.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) · [Potential ransomware precursor playbook](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/playbooks/possible-ransomware-precursors.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

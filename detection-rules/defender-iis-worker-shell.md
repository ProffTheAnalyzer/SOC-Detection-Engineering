# IIS worker spawns a shell — process hunting

> **Validation:** Hunting example; not tenant-tested. **Platform:** Defender XDR advanced hunting. **Goal:** Flag IIS workers creating interactive/system interpreters.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, Child = FileName,
          ProcessCommandLine, FolderPath, SHA1,
          ProcessUniqueId, InitiatingProcessUniqueId
| order by Timestamp desc
```

## Triage

**Possible benign:** ASP.NET/application logic that invokes a command-line utility, maintenance, deployment.

**Potentially malicious:** Unexpected HTTP request just before execution, file creation in web-accessible directory, command to retrieve a payload, lateral activity, new task/service.

**Workflow:** Determine IIS app pool, request origin and application owner. Correlate server logs and exact process instance (GUID/unique key). Compare against approved deployment jobs. Assess whether the executable actually ran unapproved actions.

**Limitations:** Correlation with a request isn't in this query; obtaining IIS HTTP request logs may require other sources. Not all web compromises use a shell, and a process pair is not proof of an exploit.

Related [SOC IIS playbook](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/playbooks/suspicious-iis-child-process.md).

[DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table).

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

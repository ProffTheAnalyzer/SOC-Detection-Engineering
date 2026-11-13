# Registry Run / RunOnce value changes

> **Validation:** Hunting example; not lab-tested. **Platform:** Defender XDR `DeviceRegistryEvents`. **Goal:** Review changed user and machine startup entries.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey contains @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where ActionType in~ ("RegistryValueSet", "RegistryValueDeleted")
| project Timestamp, DeviceName, ActionType, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessUniqueId
| order by Timestamp desc
```

## Interpretation

- **Normal:** Approved application, installer, updater or endpoint management process changing auto-start.
- **Concerning:** Unapproved script in Downloads/Temp/Public, unexpected writer, newly privileged autorun, associated payload retrieval or unusual network behavior.

## Verification checklist

Confirm which registry paths and ActionType values are actually ingested on your OS/Defender versions. This substring intentionally includes `RunOnce` and possibly other longer matching keys; review full keys and adjust filters. Not all persistence mechanisms use Run keys. Correlate with process and file events; document sanctioned software rollout.

**Possible ATT&CK mapping:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) when the observed action actually serves as persistence. Mere legitimate installer update isn't an attack.

[DeviceRegistryEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table).

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

# Outbound RDP activity to multiple destinations

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceNetworkEvents` (onboarded endpoints with network telemetry).

**Objective:** Identify endpoints and initiating processes making successful network connections to multiple public IP addresses on the standard RDP port.

## KQL hunting query

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 3389
| where RemoteIPType == "Public"
| summarize Connections = count(),
            UniqueDestinations = dcount(RemoteIP),
            DestinationIPs = make_set(RemoteIP, 50)
    by DeviceName,
       InitiatingProcessFileName,
       InitiatingProcessAccountName
| where UniqueDestinations >= 5
| order by UniqueDestinations desc
```

## What the query does

The query selects successful connection events to public remote IPs on port 3389 during the past day. It groups by device name, initiating process filename and account, counts connections, estimates distinct destinations and lists up to 50 remote IPs. The five-destination threshold is an initial hunting threshold.

## Example

An unfamiliar executable generates 320 successful connection events to approximately 85 distinct public destinations on port 3389. Compare this behavior with expected remote administration and the process's purpose. This is an illustrative result.

## Investigation pivots

- Identify the process path, command line, hash, signer, parent process and executing account.
- Review destination ownership, timing, expected remote-administration activity and related process or file activity.
- Pivot into raw network events for the device and process; use DeviceId and process unique identifiers where available to distinguish individual process instances. Review authentication or RDP session evidence on relevant systems when available.

**False positives:** IT support, authorized remote administration, security assessments and other approved use of external RDP servers.

**Limitations:** A successful TCP connection is not proof of successful RDP authentication or even definitive protocol identification. The query covers the standard port and successful connection events only, not failed connection attempts or nonstandard ports. A filename/account grouping can combine separate process instances; use raw events to establish exact lineage. Distinct counts are approximate and the displayed IP list is capped.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceNetworkEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) · [Network and ransomware behavior](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/analysis/network-email-and-ransomware.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

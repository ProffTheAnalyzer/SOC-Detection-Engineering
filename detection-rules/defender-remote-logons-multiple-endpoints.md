# Remote authentication across multiple endpoints

**Platform:** Microsoft Defender XDR

**Data source:** `DeviceLogonEvents` (Defender for Endpoint authentication telemetry on destination devices).

**Objective:** Identify a source IP and account authenticating successfully to several devices through network or remote interactive logons within one day.

## KQL hunting query

```kusto
DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonSuccess"
| where LogonType in~ ("Network", "RemoteInteractive")
| where isnotempty(RemoteIP)
    and isnotempty(AccountName)
    and isnotempty(DeviceId)
| summarize Logons = count(),
            UniqueDevices = dcount(DeviceId),
            Devices = make_set(DeviceName, 50)
    by RemoteIP, AccountDomain, AccountName, LogonType
| where UniqueDevices >= 5
| order by UniqueDevices desc
```

## What the query does

The query groups successful logon events by remote source IP, account domain, account name and logon type, then counts distinct destination device IDs. The five-device threshold is illustrative. Network logons can reflect shared folders, printers or remote administration; RemoteInteractive logons can reflect RDP and related remote desktop access. DeviceName represents the affected destination device and RemoteIP the remote source. Review the actual LogonType and ActionType values in the tenant's schema.

## Example

One account from the same workstation IP records successful network logons to eight separate servers during a day. This is an illustrative result that warrants checking whether the account and source are approved for such access.

## Investigation pivots

- Inspect raw logons for the source/account and identify destination roles, precise timestamps, authentication protocols and privileges.
- Compare with expected access patterns, approved management hosts, service accounts and user activity. AccountDomain and AccountName provide context but are not globally unique; inspect AccountSid where available.
- Correlate destination process execution, administrative share access, service/task creation and unusual files. Investigate the originating endpoint's activity to establish whether movement actually occurred.

**False positives:** Backup servers, IT management platforms, shared service accounts, file-share access, jump hosts and authorized administration.

**Limitations:** This hunt counts authentication events, not confirmed lateral execution. It can miss distributed or low-volume movement, incomplete endpoint coverage, logons with missing source IP and other logon types. Shared source IPs and account-name collisions may mix unrelated activity; distinct counts are approximate, and the device list is capped at 50. The threshold is not a universal detection rule.

**Validation:** Hunting example; not yet tested against a tenant.

[DeviceLogonEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) · [SOC NTLM authentication playbook](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/playbooks/suspicious-ntlm-authentication.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

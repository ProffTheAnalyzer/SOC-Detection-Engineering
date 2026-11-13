# Successful Entra sign-ins from an unfamiliar IP

**Platform:** Microsoft Sentinel / Log Analytics

**Data source:** `SigninLogs` (requires Entra sign-in telemetry and sufficient retention).

**Objective:** Find successful sign-ins from user/IP combinations first observed within the last day, using the available 30-day sign-in history.

## KQL hunting query

```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where ResultType == "0"
| where isnotempty(UserPrincipalName) and isnotempty(IPAddress)
| summarize FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            SignInCount = count()
    by UserPrincipalName, IPAddress
| where FirstSeen >= ago(1d)
| order by FirstSeen desc
```

## What the query does

| Query element | Purpose |
|---|---|
| `ago(30d)` | Reviews up to 30 days of available sign-in history |
| `ResultType == "0"` | Limits the hunt to successful sign-ins |
| `summarize ... by UserPrincipalName, IPAddress` | Groups events by each user and IP address |
| `min(TimeGenerated)` / `max(TimeGenerated)` | Finds the first and last observed successful sign-ins for the pair |
| `count()` | Counts successful sign-in events for the pair |
| `FirstSeen >= ago(1d)` | Returns pairs first observed in the past day |

## Example

If a user normally signs in from `192.0.2.10`, but successfully signs in today from `198.51.100.20` for the first time in the available history, the second IP may appear in the results. These are illustrative documentation addresses.

## Investigation pivots

- Review the user's sign-in history and the device, application, location, MFA and Conditional Access details associated with the new IP.
- Check whether a corporate VPN, mobile carrier, proxy or travel explains the change.
- Investigate unusual post-sign-in activity, such as unexpected app access or identity changes.

**Limitations:** First seen means first observed in the available query window, not the user's first-ever use of the IP. New accounts, incomplete retention and rotating IP addresses can produce expected results. This query identifies unfamiliar IPs, not impossible travel or confirmed account compromise. It summarizes user/IP pairs rather than returning each individual sign-in.

**Validation:** Hunting example; not yet tested against a tenant.

[Microsoft Entra sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins) · [SOC identity and cloud behavior guide](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/analysis/identity-and-cloud-behavior.md)

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

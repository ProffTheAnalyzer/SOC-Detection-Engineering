# Potential password spraying

**Platform:** Microsoft Sentinel / Log Analytics

**Data source:** `SigninLogs` (Entra sign-in telemetry and sufficient coverage).

**Objective:** Identify IP addresses associated with invalid username or password sign-in failures against multiple identities within one hour.

## KQL hunting query

```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50126"
| where isnotempty(IPAddress)
    and isnotempty(UserPrincipalName)
| summarize FailedAttempts = count(),
            TargetedUsers = dcount(UserPrincipalName),
            Users = make_set(UserPrincipalName, 50)
    by IPAddress
| where TargetedUsers >= 5
| order by FailedAttempts desc
```

## What the query does

ResultType `50126` indicates invalid username or password. The query counts failures, estimates distinct targeted users with `dcount()`, and collects up to 50 distinct usernames per IP. It returns sources associated with at least five distinct users within the one-hour lookback.

## Example

A source IP generates 26 invalid credential failures against approximately 18 distinct users in an hour. This is an illustrative result, not actual tenant telemetry.

## Investigation pivots

- Review IP ownership, ASN, proxy or VPN context and the targeted users and applications.
- Check successful sign-ins from the same source and account-level activity across other IPs and time windows.
- Review MFA, Conditional Access, device context, user reports and subsequent resource access where available.

**False positives:** Shared NAT or proxy addresses, misconfigured authentication systems, stale credentials and authorized security tests.

**Limitations:** The five-user threshold is illustrative and should be adjusted for the environment. This hunt cannot show that the same password was attempted against every user. It covers one failure code and a single-source pattern; distributed or low-and-slow spraying and other error codes may be missed. The distinct count is approximate and the displayed user list is capped.

**Validation:** Hunting example; not yet tested against a tenant.

[SigninLogs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) · [Microsoft Entra sign-in error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes) · [Identity and cloud behavior](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/analysis/identity-and-cloud-behavior.md)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

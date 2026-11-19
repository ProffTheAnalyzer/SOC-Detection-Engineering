# Counting, grouping, distinct values, and investigation timelines

**Focus:** `summarize`, `count()`, `dcount()`, `make_set()`, `min()`, `max()`, `sum()`, `top` and `sort`.

**Example tables:** `AuthenticationEvents`, `Email` and `NetworkFlow` (illustrative exercise schemas; not default Sentinel tables).

## Count logins by IP

```kusto
AuthenticationEvents
| where result == "Successful Login"
| summarize SuccessfulLogins = count() by src_ip
| top 1 by SuccessfulLogins desc
```

`summarize` groups rows with the same `src_ip`; `count()` counts all matching records in each group. `top 1` selects the source IP with the most successful login records. Multiple logins do not automatically mean compromise.

## Failed attempts by user and source IP

```kusto
AuthenticationEvents
| where result == "Failed Login"
| summarize FailedAttempts = count() by username, src_ip
| order by FailedAttempts desc
```

Grouping by **both** `username` and `src_ip` gives a separate count for each pair. This helps distinguish one IP failing across many users from many IPs failing for one user.

## Unique usernames per source IP

```kusto
AuthenticationEvents
| where result == "Failed Login"
| summarize UniqueAccounts = dcount(username) by src_ip
| where UniqueAccounts > 1
| order by UniqueAccounts desc
```

`dcount()` returns an **approximate distinct count**, useful for high-volume investigation. An IP with failures against many accounts could indicate password spraying, shared enterprise egress, a misconfigured application, or security testing. Password spraying requires more supporting evidence.

Similarly, identify the IP with successful logins to the largest number of accounts:

```kusto
AuthenticationEvents
| where result == "Successful Login"
| summarize UniqueAccounts = dcount(username) by src_ip
| top 1 by UniqueAccounts desc
```

## Multiple aggregations in one query

```kusto
AuthenticationEvents
| where result == "Failed Login"
| summarize TotalAttempts = count(),
            UniqueAccounts = dcount(username),
            FirstSeen = min(timestamp),
            LastSeen = max(timestamp)
    by src_ip
| order by TotalAttempts desc
```

This produces **event volume**, **number of targeted identities**, and **first/last timestamps** for each source IP. An event timeline can help correlate attempted access with account lockouts or later successful logins.

**About `password_hash`:** Some synthetic training datasets may contain an artificial `password_hash` field. Ordinary Microsoft Entra `SigninLogs` records do **not** expose the attempted password or a comparable hash for each authentication attempt. You cannot infer that a single password was tried against multiple users from standard sign-in failures alone. Do not publish a password-hash-grouping query as if it worked on actual Microsoft Sentinel `SigninLogs`.

## Emails sent and distinct recipients

```kusto
Email
| summarize TotalSent = count(),
            UniqueRecipients = dcount(recipient)
    by sender
| order by TotalSent desc
```

This reports email volume and approximate unique recipient count for each sender.

To find the **sixth** sender after ranking by total emails:

```kusto
Email
| summarize TotalSent = count() by sender
| order by TotalSent desc, sender asc
| serialize Rank = row_number()
| where Rank == 6
```

The second sort key makes ranking deterministic for tied email counts; the row chosen is sixth **by ranking order**, not necessarily a unique sixth-highest count.

## Find the first and last matching email

```kusto
Email
| where sender == "sample@example.org"
| where link contains "google.com"
| summarize FirstSeen = min(timestamp),
            LastSeen = max(timestamp)
    by sender
```

This finds the first and last time the selected substring appears in the `link` field for that sender. **Substring matching is not URL domain validation:** a lookalike hostname or a query parameter can contain `google.com`. To prove a particular domain, parse and compare the actual hostname.

## `make_set()`: collect unique values

```kusto
Email
| where link contains "baddomain.example"
| summarize Recipients = make_set(recipient, 100) by subject
```

Unlike `dcount()`, `make_set()` creates an array of distinct values. The `100` cap limits the maximum output values. This can help scope email recipients grouped by subject; verify actual URL hostnames and email delivery status before concluding campaign impact.

Find users who logged in from more than five distinct IPs:

```kusto
AuthenticationEvents
| where result == "Successful Login"
| summarize AllIPs = make_set(src_ip, 100),
            UniqueIPs = dcount(src_ip)
    by username
| where UniqueIPs > 5
| order by UniqueIPs desc
```

VPNs, roaming devices, NAT and mobile networks may explain multiple addresses. `UniqueIPs` may exceed the 100-item displayed list; `dcount()` is approximate.

## References

- [`summarize`](https://learn.microsoft.com/en-us/kusto/query/summarize-operator)
- [`dcount()`](https://learn.microsoft.com/en-us/kusto/query/dcount-aggregation-function)
- [`make_set()`](https://learn.microsoft.com/en-us/kusto/query/make-set-aggregation-function)
- [`SigninLogs` table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

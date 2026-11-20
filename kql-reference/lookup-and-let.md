# KQL lookup, let and in: filtering and enrichment

**Focus:** Filtering one table using values from another; adding directory information to logs; understanding `$left` and `$right`.

**Example schemas:** `Employees` (name, role, email_addr, username, ip_addr), `ProxyEvents` (timestamp, src_ip, domain, url), `Email` (timestamp, sender, recipient, links). **These are exercise datasets, not built-in Microsoft Sentinel or Defender tables.**

## Use let + in to filter employees using proxy activity

```kusto
let VictimIPs =
    ProxyEvents
    | where domain in ("api-sync-updates.top", "update-cdn-service.xyz")
    | distinct src_ip;
Employees
| where ip_addr in (VictimIPs)
| project name, role, ip_addr
```

`let` names the intermediate table, `distinct` returns one column of source IPs, and `in` checks whether an employee IP occurs in that set. The final result contains **employee fields**, not individual proxy request details.

**Investigative question:** Which employee records correspond to IPs that accessed either selected domain? IP-to-user attribution is not definitive in the presence of DHCP, NAT, shared hosts or VPNs.

## Use lookup to enrich proxy events with employee details

```kusto
ProxyEvents
| where domain in ("api-sync-updates.top", "update-cdn-service.xyz")
| lookup kind=leftouter (
    Employees
    | project name, role, ip_addr
) on $left.src_ip == $right.ip_addr
| project-reorder timestamp, src_ip, name, role, url
```

- `ProxyEvents` is the **left** event table; `Employees` is the **right** reference table.
- `$left.src_ip` and `$right.ip_addr` identify the matching fields.
- The `on` clause defines the relationship. If both keys are named `common_field`, use `Table1 | lookup Table2 on common_field`.
- `project-reorder` moves the requested columns to the front while retaining the other columns.

**Important:** A lookup **defaults to leftouter**, retaining unmatched event rows with null reference fields. Only matched events are returned with `lookup kind=inner`. This corrects the common misconception that lookup always drops unmatched rows.

## Enrich email recipients

```kusto
Email
| where sender == "noreply@whiskersandwonders-hr.com"
| lookup kind=leftouter (
    Employees
    | project email_addr, name, role, ip_addr
) on $left.recipient == $right.email_addr
| project-reorder timestamp, sender, recipient, name, role, ip_addr
```

Each matching employee contributes their name, role and IP details. Email rows with no employee match remain, but their employee fields are null. Change to `kind=inner` when only recognized employees matter.

## Why the direction of lookup matters

An exercise might start with employee records:

```kusto
Employees
| where role == "Cat Care Specialist"
| project name, ip_addr
| lookup (
    ProxyEvents
) on $left.ip_addr == $right.src_ip
| where isnotempty(url)
```

The final filter selects employees with matching proxy records. However, **putting a large proxy-event table on the right of lookup is usually unsuitable**: Kusto broadcasts the right-side reference data and expects it to be relatively small. An event-first version is generally better:

```kusto
ProxyEvents
| lookup kind=inner (
    Employees
    | where role == "Cat Care Specialist"
    | project name, ip_addr
) on $left.src_ip == $right.ip_addr
| project timestamp, name, src_ip, url
```

A lookup can return **multiple rows per left event** when the right table has duplicate matching keys. It does not enforce one-to-one correspondence; confirm the identity/IP mapping before counting employees or browsing sessions.

## Which operator should I choose?

| Approach | Good for | Result |
|---|---|---|
| `let` + `in` | Filter one table by a set of values obtained from another | Only the final filtered table's columns |
| `lookup` | Enrich an event table using a **small** reference/dimension table | Adds matching right-side fields; defaults to leftouter |
| `join` | Multiple join types, nonmatch checks, or event-to-event correlation | Exact row behavior depends on `kind=`; multiple matches can multiply rows |

**Summary:** Use `in` for membership, `lookup` for enrichment, and `join` when you need more control over matching and nonmatching records.

## References

- [Kusto lookup operator](https://learn.microsoft.com/en-us/kusto/query/lookup-operator)
- [Kusto join operator](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- [Kusto let statement](https://learn.microsoft.com/en-us/kusto/query/let-statement)
- [Kusto in operator](https://learn.microsoft.com/en-us/kusto/query/in-cs-operator)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

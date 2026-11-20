# KQL join types: matching and missing activity

**Focus:** Understanding the left and right tables, choosing a join type, and interpreting missing events. **Example tables** `Email`, `Employees` and `AuthenticationEvents` are illustrative exercise datasets.

## The basic join structure

```kusto
Email
| join kind=inner (
    Employees
) on $left.recipient == $right.email_addr
```

`Email` is the **left** table and `Employees` is the **right** table. The two fields named in `on` are compared for equality. Multiple matching conditions may be separated by commas.

**Important default:** A KQL `join` without `kind=` uses **innerunique**, which deduplicates left join keys. Use explicit `kind=inner` if every matching left row matters; duplicate matches on either side may increase output rows.

## Join type reference

| Type | Rows retained | Common question |
|---|---|---|
| `inner` | Only matching rows from both tables | Which email recipients are employees? |
| `leftouter` | Every left row, and matching right columns | Which messages went to employees or other recipients? |
| `rightouter` | Every right row, and matching left columns | Which employees received or did not receive a message? |
| `fullouter` | All records from both sides, matched where possible | Which records exist in either dataset? |
| `leftanti` | Only left rows without a match on the right | Which employees have no recorded authentication activity? |
| `rightanti` | Only right rows without a match on the left | Which directory entries have no matching events? |
| `leftsemi` | Left rows with a right match; no right columns | Which employees have at least one authentication event? |
| `rightsemi` | Right rows with a left match; no left columns | Which reference entries occur in the event data? |
| `innerunique` | Inner match after left-key deduplication | Default behavior if no join kind is given |

## Leftouter versus inner

```kusto
Email
| where sender == "sample@user.org"
| join kind=leftouter Employees
    on $left.recipient == $right.email_addr
| project-reorder timestamp, sender, recipient, name, ip_addr
```

This keeps **all email records** for the selected sender, including recipients not found in the employee directory. Missing employee fields are null.

```kusto
Email
| where sender == "sample@user.org"
| join kind=inner Employees
    on $left.recipient == $right.email_addr
| project-reorder timestamp, sender, recipient, name, ip_addr
```

This keeps only the emails whose recipients are found in the employee directory.

With a leftouter join, the output contains **at least as many rows as the left side**, but duplicate matches can **multiply** rows. Use a stable message/event identifier when calculating counts.

## Rightouter: which employees were never emailed?

```kusto
Email
| where sender == "sample@user.org"
| join kind=rightouter Employees
    on $left.recipient == $right.email_addr
| where isnull(timestamp)
| project name, email_addr, role
```

The right side is Employees, so all employees are retained. `isnull(timestamp)` selects records with no matching **left-side email timestamp**, assuming Employees does not also have a column named `timestamp`.

A cleaner alternative for a nonmatch-only question is:

```kusto
Employees
| join kind=leftanti (
    Email
    | where sender == "sample@user.org"
) on $left.email_addr == $right.recipient
| project name, email_addr, role
```

## Leftanti: employees with no recorded authentication

```kusto
Employees
| join kind=leftanti (
    AuthenticationEvents
    | where timestamp >= datetime(2025-06-01)
        and timestamp < datetime(2025-06-08)
) on $left.username == $right.username
| project name, username, role
```

Returns employees with **no matching authentication events in the specified week** (June 1–7). Using a half-open date interval includes the complete final day.

To ask which employee has no auth events in the **entire available dataset**, omit the right-side date filter:

```kusto
Employees
| join kind=leftanti AuthenticationEvents
    on $left.username == $right.username
| project name, username
```

No matching telemetry does not prove an account is dormant. Logs may be missing, outside retention or collected in another source.

## Leftsemi: keep employees who have at least one auth event

```kusto
Employees
| join kind=leftsemi AuthenticationEvents
    on $left.username == $right.username
| project name, username
```

Unlike an inner join, this does not generate one employee row per matching authentication event. No right-side columns are added.

## Choosing the join

Use `inner` for matched records, `leftouter` to preserve your starting events, `leftanti` for nonmatches, and `leftsemi` for existence without adding other columns. For enrichment with a small reference table, see [lookup and let](lookup-and-let.md).

## References

- [Kusto join operator](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- [Kusto leftouter join](https://learn.microsoft.com/en-us/kusto/query/join-leftouter)
- [Kusto leftanti join](https://learn.microsoft.com/en-us/kusto/query/join-leftanti)
- [Kusto innerunique join](https://learn.microsoft.com/en-us/kusto/query/join-innerunique)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

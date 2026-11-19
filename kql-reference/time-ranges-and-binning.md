# Time ranges and time-bucket analysis in KQL

**Focus:** Filtering complete days and using `bin()` to reveal changes in activity.

**Example tables:** `AuthenticationEvents` and `NetworkFlow` (illustrative exercise schemas). Adjust field names and timestamp columns for your actual data source.

## Exact date filtering

To find the most bytes received by a destination on February 5, 2024:

```kusto
NetworkFlow
| where timestamp >= datetime(2024-02-05)
    and timestamp < datetime(2024-02-06)
| summarize TotalBytesReceived = sum(bytes) by dest_ip
| top 1 by TotalBytesReceived desc
```

The **inclusive start and exclusive next-day boundary** covers the full calendar day regardless of milliseconds or finer timestamp precision. The name `TotalBytesReceived` is only accurate if the table's `bytes` field measures received bytes for the destination; network datasets differ in directionality.

Another approach uses the calendar functions:

```kusto
NetworkFlow
| where monthofyear(timestamp) == 2 and dayofmonth(timestamp) == 5
| summarize TotalBytes = sum(bytes) by dest_ip
| top 10 by TotalBytes desc
```

**Caution:** The second query matches **February 5 in every year** available in the data. Use exact date boundaries when you need a specific year. On larger datasets, direct comparisons to the timestamp column are also preferable for efficient time filtering.

## `startofday()`

`startofday()` returns the start (midnight) of the day for a given datetime. For example, retrieve all events on May 1:

```kusto
AuthenticationEvents
| where timestamp >= startofday(datetime(2024-05-01))
    and timestamp < startofday(datetime(2024-05-02))
```

This includes May 1 but excludes midnight at the beginning of May 2.

## `endofday()`

`endofday()` returns the last instant of the specified day:

```kusto
AuthenticationEvents
| where timestamp <= endofday(datetime(2024-05-07))
| where result == "Failed Login"
```

This includes events on or **before May 7, 2024** (including earlier days in the retained data). If you only want May 7, add a lower bound. The preferred alternative for an exact range is `timestamp >= datetime(2024-05-07) and timestamp < datetime(2024-05-08)`.

**`between` is inclusive on both sides.** For instance:

```kusto
AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where result == "Failed Login"
```

This stops at **midnight at the start of May 7**, not the end of that day. To include all seven dates:

```kusto
AuthenticationEvents
| where timestamp >= datetime(2024-05-01)
    and timestamp < datetime(2024-05-08)
| where result == "Failed Login"
```

## `bin()`: see activity over time

The `bin()` function rounds timestamps down to the beginning of a fixed interval, so events in the same interval can be aggregated together:

```kusto
AuthenticationEvents
| where result == "Failed Login"
| summarize HourlyFailures = count() by TimeBucket = bin(timestamp, 1h)
| order by TimeBucket asc
```

If a host normally has five failed logins per hour but the count rises to 500, this could indicate an authentication attack or an application issue. Investigate the accounts, source IPs, hosts and failure reasons before determining the cause.

Common bucket sizes:

| Bucket | Meaning | Investigation use |
|---|---|---|
| `1m` | 1 minute | Rapid bursts or short-lived attacks |
| `5m` | 5 minutes | Burst patterns or repetitive connections |
| `1h` | 1 hour | Authentication trends and alert volumes |
| `1d` | 1 day | Multi-day trends and changes in baseline |

`bin()` does **not** automatically create rows for intervals with zero activity. A chart requiring continuous zero-filled time buckets needs additional query logic.

## Other patterns

```kusto
NetworkFlow
| where timestamp >= datetime(2024-02-05)
    and timestamp < datetime(2024-02-06)
| summarize TotalBytes = sum(bytes) by dest_ip
| top 10 by TotalBytes desc
```

This identifies the top ten destination IPs by the table's recorded byte measure for that day, useful when reviewing anomalous transfer volume.

**Time zone:** Kusto datetime values are generally handled in UTC. Make sure your intended investigation day matches the correct local-to-UTC time boundaries if your case uses a local time zone.

## References

- [Microsoft Kusto `bin()`](https://learn.microsoft.com/en-us/kusto/query/bin-function)
- [`startofday()`](https://learn.microsoft.com/en-us/kusto/query/startofday-function), [`endofday()`](https://learn.microsoft.com/en-us/kusto/query/endofday-function)
- [`between` operator](https://learn.microsoft.com/en-us/kusto/query/between-operator)
- [KQL query best practices](https://learn.microsoft.com/en-us/kusto/query/best-practices)

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

# Derived fields, off-hours analysis, and conditional logic

**Focus:** `extend`, `hourofday()`, `iff()`, `case()` and simple event analysis using illustrative `AuthenticationEvents` data.

## `extend`: add a calculated column

```kusto
AuthenticationEvents
| take 100
| extend HourOfDay = hourofday(timestamp)
```

`extend` keeps the existing columns while adding `HourOfDay`. `hourofday()` returns a number from 0 to 23 for the input datetime.

## Find authentication events during off-hours

```kusto
AuthenticationEvents
| extend HourOfDay = hourofday(timestamp)
| where HourOfDay < 6 or HourOfDay >= 18
| count
```

This counts events before 06:00 or at/after 18:00 in the timezone represented by `timestamp`. Kusto datetimes are commonly UTC; convert thoughtfully for local working hours, time zones and daylight saving rules. Off-hours activity can be normal for global teams, service accounts or scheduled jobs.

For context by user:

```kusto
AuthenticationEvents
| extend HourOfDay = hourofday(timestamp)
| where HourOfDay < 6 or HourOfDay >= 18
| summarize OffHoursEvents = count() by username
| order by OffHoursEvents desc
```

## `iff()`: two-way logic

Syntax: `iff(condition, value_if_true, value_if_false)`.

```kusto
AuthenticationEvents
| extend Status = iff(result == "Successful Login", "OK", "OTHER")
| project timestamp, username, src_ip, result, Status
```

The `OTHER` fallback is intentional: any value other than `"Successful Login"` is not necessarily a failed login. It may be missing, unknown or a different result.

## `case()`: multiple conditions

```kusto
AuthenticationEvents
| extend Status = case(
    result == "Successful Login", "SUCCESS",
    result == "Failed Login", "FAILURE",
    "OTHER"
)
| summarize Events = count() by Status
```

`case()` evaluates conditions in order and returns the value for the first match, with a final fallback. This is more explicit than labelling every non-success event a failure.

## Analyst interpretation

Use computed columns to make complex logs easier to pivot. These labels describe **how the query classified a record**, not a completed security determination. Review real field values and schemas before bringing the logic into Sentinel or Defender XDR.

## References

- [`iff()`](https://learn.microsoft.com/en-us/kusto/query/iff-function)
- [`hourofday()`](https://learn.microsoft.com/en-us/kusto/query/hour-of-day-function)
- [KQL common operators](https://learn.microsoft.com/en-us/kusto/query/tutorials/learn-common-operators)

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

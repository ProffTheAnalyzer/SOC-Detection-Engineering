# KQL Query Reference

My reference for common KQL operators and functions used in SOC investigations, including date filtering, time-based trends, aggregations, unique counts, lists, and conditional analysis.

These examples use **illustrative exercise tables**, not built-in Microsoft Sentinel or Defender XDR schemas:

| Sample table | Example fields |
|---|---|
| `AuthenticationEvents` | `timestamp`, `result`, `username`, `src_ip` |
| `NetworkFlow` | `timestamp`, `src_ip`, `dest_ip`, `bytes` |
| `Email` | `timestamp`, `sender`, `recipient`, `subject`, `link` |

The examples assume `timestamp` is a `datetime` value and that `bytes` represents bytes received for the flow direction being analyzed. Field names and directionality must be checked against the real data source. For Sentinel, a common sign-in table is `SigninLogs` with `TimeGenerated`, `ResultType`, `UserPrincipalName` and `IPAddress`; Defender XDR advanced hunting tables commonly use `Timestamp` and other table-specific columns.

## Topics

| Topic | What I use it for |
|---|---|
| [Time ranges, `startofday()`, `endofday()` and `bin()`](time-ranges-and-binning.md) | Investigate specific days, avoid date boundary mistakes, and find spikes over time |
| [`summarize`, `dcount()`, `make_set()`, `min()` and `max()`](aggregations-and-investigation-pivots.md) | Count events, identify distinct accounts/IPs, collect unique values, and reconstruct timelines |
| [`extend`, `hourofday()`, `iff()` and `case()`](derived-fields-and-conditions.md) | Add calculated columns, find off-hours activity, and classify events |

These are **query-learning examples**, not validated production detections. A query match starts an investigation; it does not establish a malicious action.

[Back to Detection Engineering](../README.md)

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

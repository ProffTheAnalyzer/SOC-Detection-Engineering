# KQL Query Reference

My reference for common KQL operators and functions used in SOC investigations, including date filtering, time-based trends, aggregations, unique counts, lists, and conditional analysis.

These examples use **illustrative exercise tables**, not built-in Microsoft Sentinel or Defender XDR schemas:

| Sample table | Example fields |
|---|---|
| `AuthenticationEvents` | `timestamp`, `result`, `username`, `src_ip` |
| `NetworkFlow` | `timestamp`, `src_ip`, `dest_ip`, `bytes` |
| `Email` | `timestamp`, `sender`, `recipient`, `subject`, `link` (string) or `links` (array) |
| `Employees` | `name`, `role`, `email_addr`, `username`, `ip_addr` |
| `ProxyEvents` | `timestamp`, `src_ip`, `domain`, `url` |

The examples assume `timestamp` is a `datetime` value and that the email `links` field is an array where used. The actual meaning of `bytes` depends on network flow directionality and the sensor's schema. Field names and directionality must be checked against the real data source. For Sentinel, a common sign-in table is `SigninLogs` with `TimeGenerated`, `ResultType`, `UserPrincipalName` and `IPAddress`; Defender XDR advanced hunting tables commonly use `Timestamp` and other table-specific columns.

## Topics

| Topic | What I use it for |
|---|---|
| [Time ranges, `startofday()`, `endofday()` and `bin()`](time-ranges-and-binning.md) | Investigate specific days, avoid date boundary mistakes, and find spikes over time |
| [`summarize`, `dcount()`, `make_set()`, `min()` and `max()`](aggregations-and-investigation-pivots.md) | Count events, identify distinct accounts/IPs, collect unique values, and reconstruct timelines |
| [`extend`, `hourofday()`, `iff()` and `case()`](derived-fields-and-conditions.md) | Add calculated columns, find off-hours activity, and classify events |
| [`lookup`, `let` and `in`](lookup-and-let.md) | Enrich network/email events with employee details or filter by a set of IPs |
| [`join` types, matches and nonmatches](joins-and-nonmatches.md) | Left/right table logic, inner/outer/semi/anti, and identifying absent events |
| [`parse`, `split()`, `parse_url()` and `mv-expand`](parsing-and-arrays.md) | Extract URL hosts, split addresses, and turn multiple links into rows |
| [Phishing email, proxy and follow-on URL correlation](phishing-correlation.md) | Relate email recipients to proxy observations while separating visits from confirmed clicks |

These are **query-learning examples**, not validated production detections. A query match starts an investigation; it does not establish a malicious action.

[Back to Detection Engineering](../README.md)

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

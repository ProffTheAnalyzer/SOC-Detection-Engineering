# Parsing URLs, splitting strings, and expanding arrays in KQL

**Focus:** Converting strings and dynamic arrays into fields suitable for filtering, enrichment and joining.

**Exercise tables:** `ProxyEvents` (url, src_ip, timestamp), `Employees` (email_addr), `Email` (timestamp, sender, recipient, links). Some exercises use a single `link` string; other exercises use a dynamic `links` array. **Check the schema before reusing a query.**

## parse: extract fields using fixed anchors

```kusto
ProxyEvents
| take 100
| parse url with "https://" ParsedDomain "/" *
| project url, ParsedDomain
```

For `https://evil.example/malware/download.exe`, this pattern captures `evil.example`.

| Segment | Role |
|---|---|
| `"https://"` | Literal anchor before the domain |
| `ParsedDomain` | Captured text until the next literal |
| `"/"` | Marks the end of the captured domain |
| `*` | Ignores the remainder |

**Interpretation:** A parse pattern acts as a template. Fixed strings provide boundaries and named variables capture content between them. The example assumes HTTPS and a slash after the host; it can fail on HTTP URLs, URLs without a path, or other formats. It is a simple teaching example rather than a robust URL parser.

## parse_url(): extract a URL's hostname more reliably

```kusto
ProxyEvents
| extend Domain = tostring(parse_url(url).Host)
| project timestamp, src_ip, url, Domain
```

`parse_url()` returns a dynamic object for URL components; `.Host` accesses the host, and `tostring()` converts it to a string for analysis. It is generally preferable to a hand-written parse template for complete absolute URLs.

```kusto
ProxyEvents
| extend Domain = tostring(parse_url(url).Host)
| where Domain =~ "api-sync-updates.top"
| summarize Requests = count(),
            FirstSeen = min(timestamp),
            LastSeen = max(timestamp)
    by src_ip
```

The case-insensitive equality operator `=~` checks the **extracted hostname**. This is more precise than searching a URL for a domain-like substring; a domain string could otherwise appear in a different host's URL path or query parameters. Confirm whether subdomains should be included separately.

## split(): turn a string into an indexed array

```kusto
Employees
| extend Parts = split(email_addr, "@")
| extend Username = tostring(Parts[0]),
         MailDomain = tostring(Parts[1])
| project email_addr, Username, MailDomain
```

For `alice@example.org`, `split(email_addr, "@")` produces an array like `["alice","example.org"]`. Array indexing begins at zero.

- `Parts[0]` is the content before the first `@`.
- `Parts[1]` is the content after it.
- `split()` is simple delimiter-based extraction, **not** full email-address validation.

## split versus parse

| Function/operator | Use it when | Output |
|---|---|---|
| `split()` | Text uses a simple separator, such as `@` or `\` | Dynamic array; access elements by index |
| `parse` | Text has predictable fixed markers | Named columns |
| `parse_url()` | An absolute URL needs scheme/host/path details | Dynamic object with URL components |

## mv-expand: one dynamic array element per row

If `Email.links` contains several URLs, joining it directly to a single proxy `url` string is not the intended comparison. Expand the array first:

```kusto
Email
| mv-expand links to typeof(string)
| extend Domain = tostring(parse_url(links).Host)
| project timestamp, sender, recipient, links, Domain
```

**Why expand?** An email with three links becomes up to three rows, each containing one link string while preserving the email's sender, recipient and timestamp. Now `links` can be compared to `ProxyEvents.url`. The `to typeof(string)` clause converts expanded array elements to strings.

**Counting caution:** After expansion, `count()` counts **expanded link rows**, not necessarily distinct emails. Preserve a message identifier or use suitable distinct keys if you need email-level counts. An empty array contributes no expanded rows; be aware of null and mixed-type elements.

## A simplified URL-to-employee pivot

```kusto
ProxyEvents
| extend Domain = tostring(parse_url(url).Host)
| where Domain =~ "update-cdn-service.xyz"
| lookup kind=inner (
    Employees
    | project name, ip_addr
) on $left.src_ip == $right.ip_addr
| project timestamp, name, src_ip, url, Domain
```

This enriches matching proxy events with employee details. It remains **IP-based attribution**, not conclusive proof that the named person clicked the URL.

## References

- [Kusto parse operator](https://learn.microsoft.com/en-us/kusto/query/parse-operator)
- [Kusto split function](https://learn.microsoft.com/en-us/kusto/query/split-function)
- [Kusto parse_url function](https://learn.microsoft.com/en-us/kusto/query/parse-url-function)
- [Kusto mv-expand operator](https://learn.microsoft.com/en-us/kusto/query/mv-expand-operator)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

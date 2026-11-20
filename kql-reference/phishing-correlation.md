# Phishing email and proxy correlation with KQL

**Focus:** Scope recipients, enrich emails with directory information, check for matching proxy visits and investigate follow-on network activity.

**Example schemas:** `Email` (timestamp, sender, recipient, links as an array), `Employees` (email_addr, name, ip_addr), `ProxyEvents` (timestamp, src_ip, url, domain). These are **exercise datasets**, not default Microsoft telemetry. In real systems, prefer a reliable message ID, user/device identity and click telemetry where available.

## 1. Enrich phishing emails with recipients

```kusto
Email
| where sender == "noreply@whiskersandwonders-hr.com"
| lookup kind=leftouter (
    Employees
    | project email_addr, name, ip_addr
) on $left.recipient == $right.email_addr
| project-reorder timestamp, sender, recipient, name, ip_addr
```

The **Email** table is left; the **Employees** reference is right. A leftouter lookup keeps all selected email records, even those not in the directory.

## 2. Check which recipients have matching proxy visits

```kusto
Email
| where sender == "noreply@whiskersandwonders-hr.com"
| mv-expand links to typeof(string)
| where tostring(parse_url(links).Host) =~ "update-cdn-service.xyz"
| lookup kind=inner (
    Employees
    | project email_addr, ip_addr
) on $left.recipient == $right.email_addr
| join kind=leftouter (
    ProxyEvents
    | where tostring(parse_url(url).Host) =~ "update-cdn-service.xyz"
    | project src_ip, url, VisitedAt = timestamp
) on $left.ip_addr == $right.src_ip,
     $left.links == $right.url
| project SentAt = timestamp, sender, recipient, ip_addr,
          links, VisitedAt
```

The stages are:

1. Find emails from the selected sender and expand each URL from the `links` array.
2. Filter the expanded links by actual hostname.
3. Enrich each recipient with their reference IP.
4. Leftouter join proxy observations on both IP and **exact URL**; keep emails even when no visit matches.
5. Display the email timestamp, recipient, URL, IP and observed proxy time.

**Important:** The leftouter join by itself can match visits that happened **before** the email. If the question asks about activity after delivery, enforce the time relationship when building your matched-visit set (next section). A proxy request may come from a browser, automated scanner, preview tool or another user sharing an IP. It is not definitive proof of a human click.

## 3. Find emails with no matching proxy visit after delivery

Use a `leftanti` join for the nonmatch question, after calculating only visits that occurred at or after the email timestamp:

```kusto
let PhishingLinks =
    Email
    | where sender == "noreply@whiskersandwonders-hr.com"
    | mv-expand links to typeof(string)
    | where tostring(parse_url(links).Host) =~ "api-sync-updates.top"
    | lookup kind=inner (
        Employees
        | project email_addr, ip_addr
    ) on $left.recipient == $right.email_addr
    | project SentAt = timestamp, recipient, ip_addr, links;
let ObservedVisits =
    PhishingLinks
    | join kind=inner (
        ProxyEvents
        | project src_ip, url, VisitedAt = timestamp
    ) on $left.ip_addr == $right.src_ip,
         $left.links == $right.url
    | where VisitedAt >= SentAt
    | distinct recipient, SentAt, links;
PhishingLinks
| join kind=leftanti ObservedVisits
    on recipient, SentAt, links
| summarize LinksWithoutObservedVisit = make_set(links, 50)
    by recipient, ip_addr
```

**Meaning:** These recipients received a matching phishing URL, but the available proxy data has **no matching IP + exact-URL visit on or after the email timestamp**. This is not definitive proof that they never clicked.

A simpler `leftouter` + `isnull(VisitedAt)` approach works for an existence check if the right-side visits are **already restricted** to valid post-delivery matches. Applying `where VisitedAt >= SentAt` immediately after a leftouter join drops unmatched rows, which can accidentally erase the "didn't click" population.

**Row and identity caveats:** If a user has several emails with the same link at the same timestamp, this example cannot distinguish those instances. If different users share an egress IP, a visit may be incorrectly attributed. For reliable email-level measurements, use a unique message key and actual URL click events when possible. Join results can multiply when several proxy events match one link.

## 4. Identify proxy activity from IPs with observed matching visits

This matches the `let ClickedIPs` approach and then explores all recorded proxy traffic from those addresses:

```kusto
let ClickedIPs =
    Email
    | where sender == "sample@user.com"
    | mv-expand links to typeof(string)
    | lookup kind=inner (
        Employees
        | project email_addr, ip_addr
    ) on $left.recipient == $right.email_addr
    | join kind=inner (
        ProxyEvents
        | project src_ip, url, ClickTime = timestamp
    ) on $left.ip_addr == $right.src_ip,
         $left.links == $right.url
    | where ClickTime >= timestamp
    | distinct src_ip;
ProxyEvents
| where src_ip in (ClickedIPs)
| extend Domain = tostring(parse_url(url).Host)
| summarize FirstSeen = min(timestamp),
            LastSeen = max(timestamp),
            Requests = count(),
            URLs = make_set(url, 50)
    by src_ip, Domain
| order by LastSeen desc
```

This returns **all available browsing events for those IPs**, including events before the observed phishing URL visit. It does **not** automatically mean the follow-on destinations are C2.

## 5. Restrict the follow-on analysis to activity after the first matched visit

```kusto
let FirstObservedVisitByIP =
    Email
    | where sender == "sample@user.com"
    | mv-expand links to typeof(string)
    | lookup kind=inner (
        Employees
        | project email_addr, ip_addr
    ) on $left.recipient == $right.email_addr
    | project SentAt = timestamp, ip_addr, links
    | join kind=inner (
        ProxyEvents
        | project src_ip, url, VisitAt = timestamp
    ) on $left.ip_addr == $right.src_ip,
         $left.links == $right.url
    | where VisitAt >= SentAt
    | summarize FirstVisit = min(VisitAt) by src_ip;
ProxyEvents
| join kind=inner FirstObservedVisitByIP on src_ip
| where timestamp > FirstVisit
| extend Domain = tostring(parse_url(url).Host)
| summarize FirstSeen = min(timestamp),
            LastSeen = max(timestamp),
            Requests = count(),
            URLs = make_set(url, 50)
    by src_ip, Domain
| order by LastSeen desc
```

**Investigative reasoning:** After finding a proxy request matching the email link, identify later domains and URLs contacted by the same source IP. Compare timing, request regularity, process attribution, reputation, user authentication and endpoint events before considering C2, credential theft or a secondary payload.

**False positives and gaps:** URL prefetch/scanners, proxies or NAT sharing an IP, missing proxy logs, differing URL normalization, redirects, alternate devices, and email recipients whose IP assignments changed over time. A later visit is a **temporal correlation**, not proof the phishing email caused it.

## Further reading

- [Lookup, let and membership filtering](lookup-and-let.md)
- [Join types and missing activity](joins-and-nonmatches.md)
- [URL parsing and mv-expand](parsing-and-arrays.md)
- [SOC Knowledge Base: phishing URL triage](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/blob/main/playbooks/phishing-url-triage.md)
- [Kusto join operator](https://learn.microsoft.com/en-us/kusto/query/join-operator)


---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

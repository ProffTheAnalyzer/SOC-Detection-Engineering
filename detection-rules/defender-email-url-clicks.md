# Email URL-click investigation

> **Validation:** Hunting example; not tenant-tested. **Data:** Defender XDR `UrlClickEvents` and `EmailEvents` (requires relevant telemetry and licensing).

**Goal:** Link a URL click with the email that delivered it, when a matching message ID is available.

```kusto
let urlFragment = "suspicious-link.example";
let clicks =
    UrlClickEvents
    | where Timestamp > ago(7d)
    | where Url contains urlFragment
    | project ClickTime = Timestamp, AccountUpn, Url,
              ClickAction = ActionType, NetworkMessageId;
let messages =
    EmailEvents
    | where Timestamp > ago(14d)
    | project NetworkMessageId, RecipientEmailAddress,
              SenderFromAddress, Subject, DeliveryAction;
clicks
| join kind=leftouter (messages) on NetworkMessageId
| project ClickTime, AccountUpn, RecipientEmailAddress,
          SenderFromAddress, Subject, Url, ClickAction, DeliveryAction
| order by ClickTime desc
```

**Pivots:** Confirm what the click action means, identify further web activity, examine sign-in risk and scope other recipients.

**Limits:** A URL-click record does not prove credential submission. Events may be absent or lack a matching email message; analyze unmatched clicks separately. Security tooling can also generate URL visits.

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

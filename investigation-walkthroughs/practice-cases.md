# SOC practice cases — decide what is normal or suspicious

> **Practice scenarios:** These examples use synthetic logs to illustrate investigative decisions. Expand each explanation to see the investigative reasoning.

## Case A — A privileged NTLM logon

**Triage question:** Should you immediately classify this as Pass-the-Hash?

| Time (UTC) | Observation |
|---|---|
| 09:01 | Windows 4624, Logon Type 3, NTLM; `svc-backup` on `FILE-SRV1` from `BACKUP01` |
| 09:02 | `BACKUP01` makes routine SMB requests to `FILE-SRV1` |
| 09:05 | Approved backup change window begins; signed backup agent logs available |

<details>
<summary><strong>Open analyst walkthrough</strong></summary>

**Initial observation:** Network logon using NTLM.

**Potential benign explanation:** Scheduled backup job communicating with a file server.

**Next check:** Was `BACKUP01` the approved backup host? Does the service account historically perform these requests? Are any new services, unexpected remote commands or identity anomalies present?

**Disposition:** Inconclusive without validation; likely expected if backup ownership, history and changes corroborate. It is not evidence of PtH merely because the authentication was NTLM Type 3.

</details>

## Case B — IIS worker executes PowerShell

| Time (UTC) | Observation |
|---|---|
| 16:22:03 | IIS request to unusual upload path, from first-seen external IP |
| 16:22:04 | `w3wp.exe` launches `powershell.exe` with an obfuscated command |
| 16:22:05 | PowerShell downloads an executable into a temporary directory |
| 16:22:08 | That executable makes an unexpected outbound connection |
| 16:23:00 | New privileged scheduled task references the file |

<details>
<summary><strong>Open analyst walkthrough</strong></summary>

**Initial observation:** Suspicious parent-child relationship.

**Corroboration:** Independent HTTP, process, file, network and task evidence forms a linked sequence.

**Competing explanation:** Could be a custom application workflow or sanctioned test, but unusual request origin, payload retrieval and privileged persistence require urgent confirmation.

**Disposition:** Escalate promptly under incident-response policy if not explicitly authorized; collect command, task XML, hashes, request logs and follow-on activity. Do not claim exploit success *solely* from HTTP status or parent name.

</details>

## Case C — Country changes in five minutes

| Time (UTC) | Observation |
|---|---|
| 18:00 | Successful Entra sign-in from US IP |
| 18:05 | Successful sign-in with same identity from European IP |
| 18:06 | Both report a familiar managed device and expected app; second IP belongs to corporate VPN egress (synthetic context) |

<details>
<summary><strong>Open analyst walkthrough</strong></summary>

**Initial observation:** Improbable physical travel between sign-ins.

**Context:** IP geolocation represents network egress, not necessarily human location. A geographically distant corporate VPN exit can produce this pattern.

**Follow-up:** Validate IP ownership, managed-device identity, app/client, MFA/Conditional Access, account activity and token/session context.

**Disposition:** Potential false positive if VPN and authorized session explain it. If unmanaged device and suspicious admin changes followed, escalate. A geography rule alone is a hypothesis.

</details>

## Personal analyst worksheet

For each case, write **Observed / Inferred / Unknown / Benign alternative / Confidence / Next pivot / Recommendation**. Be specific: "check logs" isn't enough; name the event source, field, system and time window.

[Decision framework](normal-vs-suspicious-detection-decisions.md) · [SOC investigation playbooks](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/tree/main/playbooks).

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

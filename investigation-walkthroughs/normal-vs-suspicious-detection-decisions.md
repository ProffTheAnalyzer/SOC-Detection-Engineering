# From a suspicious query result to an analyst decision

> **Purpose:** Develop a consistent approach to interpreting security alerts and hunting results, using the observed behavior, surrounding context and corroborating evidence.

## Five questions after every KQL result

1. **What is truly observed?** Give the event source, fields, date/time, count, host and user. Do not infer malware or PtH from an event ID.
2. **Is the source complete?** Did onboarding, audit policy, license, ingestion delay or retention affect visibility?
3. **What is this entity supposed to do?** Account/host role, approved software, known admin process and change requests.
4. **What would increase or decrease confidence?** Independent corroboration, timelines and alternative explanations.
5. **What is the appropriate next action?** Close with reason, deepen investigation, or escalate with evidence.

## Mini case studies

<details>
<summary><strong>Case 1: NTLM network logon on a server</strong></summary>

**Observed:** 4624, Type 3, NTLM, from an unexpected workstation.

**Normal hypotheses:** Network share, printer, service account, admin support.

**Investigate:** Does the user usually access this asset? Is there a new System 7045 service, remote shell, admin share or additional target? Did another device run tools immediately beforehand?

**Conclusion:** Suspicious authentication pattern, **not** automatic PtH. Map to technique concepts only after establishing behavior.

</details>

<details>
<summary><strong>Case 2: a parent-child process pair</strong></summary>

**Observed:** `winword.exe` created `powershell.exe`.

**Normal hypotheses:** Document integration or sanctioned automation.

**Investigate:** Command line and decoded content, document origin, download/files created, script logs, new persistence and network traffic.

**Conclusion:** The chain and actual command matter more than an "impossible" process-pair label.

</details>

<details>
<summary><strong>Case 3: impossible travel alert</strong></summary>

**Observed:** Two geographically distant successful Entra sign-ins within minutes.

**Normal hypotheses:** Corporate VPN, mobile egress change, stale geolocation, shared session.

**Investigate:** Devices, app, MFA result, proxy egress, authenticated session and suspicious post-sign-in actions.

**Conclusion:** Geolocation may be wrong; distinguish an unusual sign-in from verified token theft.

</details>

<details>
<summary><strong>Case 4: new scheduled task</strong></summary>

**Observed:** `schtasks.exe /create` launched on one workstation.

**Normal hypotheses:** Installer, management agent, IT ticket.

**Investigate:** Created task definition, author, run-as account, executable path, trigger, origin and execution/network events.

**Conclusion:** Task creation is an observable administrative action; determine whether the resulting task is unauthorized.

</details>

## Document like an engineer

| Field | Example |
|---|---|
| Signal | Unusual NTLM Type 3 from first-seen source |
| Corroboration | Remote service created immediately afterward |
| Alternative | Approved software distribution on service window |
| Data gaps | No process telemetry from originating host |
| Assessment | Suspicious; scope lateral movement |
| Query/version | Link to exact rule file and revision |

Companion [SOC Knowledge Base behavior guides](https://github.com/ProffTheAnalyzer/SOC-Knowledge-Base/tree/main/analysis).

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

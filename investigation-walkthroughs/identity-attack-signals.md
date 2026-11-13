# Identity investigations: PtH, PtT, ticket forgery and replication

> **Scope:** Identity authentication and directory-service activity, with investigative context and limitations.

## Pass-the-Hash (PtH)

A successful NTLM network logon (for example 4624 Type 3) may be worth investigating alongside unusual remote access, services, administrative shares and process activity. **NTLM + Type 3 is not proof of PtH.** Type 9 means *NewCredentials*, not a conclusive hash-theft signal.

Correlate source/destination hosts, 4624, 4648, 4672, 4776, endpoint activity, shares and service creation.

## Pass-the-Ticket (PtT)

Investigate Kerberos access inconsistent with normal host, user and service context, including suspicious reuse patterns. Tickets may be cached, delegated or renewed; absence of an adjacent ticket request does not establish theft. Type 9 by itself does not establish PtT.

## Golden and Silver Ticket activity

Generic successful Kerberos logons are inadequate to prove a forged ticket. KDC visibility, service telemetry, ticket properties, privilege changes and collection gaps all affect interpretation. The archived legacy examples are **unvalidated hypotheses** and need redesign.

## DCSync

Unexpected replication operations can suggest misuse of directory replication privileges. Event 4662 may help if directory-service auditing/SACLs are properly configured, but replication permissions must be identified from the appropriate event fields and rights GUIDs. Not all machine accounts are safe to exclude; they can be abused.

## Skeleton Key and DCShadow

Authentication spikes or directory object changes alone are not definitive. Correlate domain controller integrity, process activity, directory service and other evidence, as well as change records.

**Analyst output:** What is observed? What is inferred? What is the benign alternative? What independent evidence supports a decision?

---

**[Cyber Profezzor — YouTube Channel](https://www.youtube.com/@thecyberprofezzor)**  
Explore my cybersecurity investigations, SOC labs, and hands-on security tutorials.

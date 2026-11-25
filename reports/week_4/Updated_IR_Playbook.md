# Phishing Incident Response Playbook

**DEPI lab · Revision 2 · 25 November 2026**

| Step | Owner role | Action and exit criteria |
| --- | --- | --- |
| Prepare | SIEM engineer | Verify the Windows agent is active and the manager can evaluate the DEPI rules. Check a bundled phishing fixture and benign control. Record rule IDs and distinguish native rule tests from indexed alerts. |
| Preserve and analyze | Analyst | Store the source EML and calculate SHA-256. Inspect headers, authentication fields, links and attachment metadata offline. Record the score and reasons. Treat message headers as claims unless a trusted mail system corroborates them. |
| Detect and correlate | SIEM engineer | Replay the saved analysis. Record the run ID and UTC time. In Threat Hunting, set the absolute time window and match the run ID, agent, rule, score and message digest. Export the expanded alert and register its digest. |
| Triage and scope | Analyst | Record the verdict and affected users or assets supported by available logs. Look for delivery, user interaction, sign-in anomalies, execution and spread. Record where telemetry is unavailable. |
| Contain, eradicate and recover | Response lead | Quarantine verified deliveries where appropriate. Use test account controls when data shows credential exposure, and isolate an authorized disposable endpoint when execution or compromise is suspected. Record the trigger, approval, action and observed outcome. Preserve evidence before cleanup where feasible. Restore from a verified clean baseline when needed and validate normal operation and monitoring. |
| Collect forensic evidence | Forensics analyst | Preserve relevant logs. Collect scoped volatile data first when it is at risk of being lost and record collector, source, UTC time and tool. Capture relevant logical files or authorized images and verify hashes on copies. Note acquisition limits and every custody transfer. |
| Close and improve | Project lead | Complete technical and executive reports, review the evidence and lead a tabletop or retrospective. Assign action owners and completion evidence. Log the outcomes and obtain team sign-off. |

## Decision thresholds

- **Suspicious email only** — Preserve the sample and review detection evidence. Record the scope and the evidence needed to verify further impact.
- **Confirmed delivery or click** — Identify affected test mailboxes, quarantine where appropriate and check gateway, identity and endpoint telemetry for follow-on activity.
- **Credential exposure or execution indicators** — Escalate to the response lead and follow authorized account or endpoint containment. Record the evidence supporting the action and verify the outcome.
- **Recovery closure** — Validate service health and detection with positive and benign controls. Record the actual observation period and any recurrence.

[NIST incident response guidance](https://csrc.nist.gov/pubs/sp/800/61/r3/final) · [NIST forensic guidance](https://csrc.nist.gov/pubs/sp/800/86/final)

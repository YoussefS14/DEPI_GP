# Week 2 — Detection, Triage & Scope

**DEPI Project 3 — Phishing, Malware & End-to-End Incident Response Case**

The Week 1 synthetic phishing and benign samples were replayed locally as single-line JSON events. The phishing event met all configured conditions for Wazuh rule `110210`; the benign event did not. This was a local check of the rule fields. Agent collection, native rule evaluation and the dashboard alert are pending verification on the lab Wazuh installation.

## 1. Alert triage notes

| Sample | Analyzer result | Evidence and triage decision | Local rule check | Live Wazuh |
| --- | --- | --- | --- | --- |
| `phish_001.eml` | High, score `70` | SPF and DMARC failures recorded in the header, a link whose destination differed from its visible text and a `.pdf.exe` attachment. Classify as simulated phishing and investigate delivery and user interaction if telemetry becomes available. | Expected match for `110210` at level `10`. All four fields matched locally. | Pending |
| `benign_001.eml` | Low, score `0` | Benign control sample. The header records SPF, DKIM and DMARC as passing. No suspicious link or attachment was reported. No escalation. | Expected to miss `110210`. The verdict and risk fields did not match. | Pending |

The local outcome corresponds to an expected true positive for the phishing fixture and an expected true negative for the benign fixture. False-positive and false-negative observations on the native Wazuh rule are pending. Two synthetic fixtures do not establish production detection rates. [Replay events](evidence/local-replay.jsonl) · [Local rule check](evidence/local-rule-check.json) · [Week 1 report](../week_1/Week_1_Phishing_Analysis_Report.md)

## 2. Initial incident timeline

All times are UTC. November 3 entries come from simulated email headers. November 23 entries are timestamps of the actual local validation run.

| When (UTC) | Event | Evidence |
| --- | --- | --- |
| 2026-11-03 03:12:00 | Date the simulated phishing message claims. | EML `Date` header |
| 2026-11-03 03:12:05 | First recorded relay hop in the simulated trace. | First chronological `Received` entry |
| 2026-11-03 03:12:10 | Final recorded hop to `mx.example.test` in the simulated trace. | Second chronological `Received` entry |
| 2026-11-23 19:15:38 | Local replay generated one event for each test sample. | `depi_replayed_at` in the JSONL |
| 2026-11-23 19:15:38 | Local rule field validation recorded both outcomes. | `validated_at_utc` in the rule check |
| Pending | Wazuh intake, alert creation and analyst review. | Add dashboard alert time and review time after live testing. |

[Phishing email trace](../week_1/evidence/email/phish_001.eml.json) · [Replay events](evidence/local-replay.jsonl) · [Local rule check](evidence/local-rule-check.json)

## 3. Scope statement

The review covers the two replayed EML reports, their email and attachment metadata, and the proposed Wazuh detection on the Windows lab endpoint. The scenario contains one intended recipient and a simulated receiving mail host. The evidence establishes the message characteristics and local rule behavior. Actual mailbox delivery, clicks, attachment execution, credential exposure, lateral spread, additional recipients and endpoint compromise remain unverified.

## 4. Affected users and assets

| User or asset | Role in the case | Evidence of impact |
| --- | --- | --- |
| `labuser@example.test` | Intended recipient in the synthetic email | Targeted in the simulation. No observed user interaction or account compromise. |
| `mx.example.test` | Receiving host in the synthetic `Received` trace | Represented in the simulated trace. No compromise evidence. |
| Windows lab endpoint | Hosts the analyzer and registered Wazuh service | The service registration is present. Agent connectivity and live collection are pending. No compromise evidence. |

No user or asset is confirmed compromised in this test case.

## 5. Escalation recommendation

Keep this run in the lab investigation queue and route the high-risk result for analyst review. For a real case with the same signals, verify delivery and scope through mail logs and look for URL access, attachment opening or execution, and anomalous sign-ins. Escalate to incident response if corroborating evidence establishes user interaction, suspicious authentication, execution or wider exposure. The current simulation supports detection and triage evidence only.

## Live verification checklist

- [x] Prepare the Windows log collector configuration, JSONL replay tool and rule `110210`.
- [x] Save local phishing and benign events, and compare their expected rule outcomes.
- [ ] Load the rule on the lab manager and save native `wazuh-logtest` output for both samples.
- [ ] Verify the Windows agent is active and replay the two events through the monitored log.
- [ ] Capture the phishing alert from Threat Hunting with rule ID, agent, run ID and timestamp. If JSON archives are enabled, also record receipt of the benign event.
- [ ] Update the timeline and triage notes with the verified Wazuh results.

[Wazuh configuration and verification commands](../../wazuh/README.md)

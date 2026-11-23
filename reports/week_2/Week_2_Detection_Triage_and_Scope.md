# Week 2 — Detection, Triage & Scope

**DEPI Project 3 — Phishing, Malware & End-to-End Incident Response Case**

The Windows agent `win11_host` forwarded the synthetic phishing replay to `wazuh-server`, which generated a level `10` alert for rule `110210`. The lab manager later decoded all 11 expanded-ruleset fixtures in Wazuh 4.14.9 `wazuh-logtest`. Eight produced the expected DEPI alert, and three controls produced no DEPI alert.

## 1. Alert triage notes

| Sample | Analyzer result | Evidence and triage decision | Wazuh rule test | Live Wazuh |
| --- | --- | --- | --- | --- |
| `phish_001.eml` | High, score `70` | SPF and DMARC failures recorded in the header, a link whose destination differed from its visible text and a `.pdf.exe` attachment. Classify as simulated phishing and investigate delivery and user interaction if telemetry becomes available. | Matched `110210` at level `10`. | One dashboard alert for `110210` from `win11_host`. |
| `benign_001.eml` | Low, score `0` | Benign control sample. The header records SPF, DKIM and DMARC as passing. No suspicious link or attachment was reported. No escalation. | Decoded as JSON. No match for `110210`. | Appended to the monitored file. Manager receipt was not independently verified. |

The phishing fixture was a true positive in the lab, and the benign fixture was a true negative in `wazuh-logtest`. The dashboard query for `110210` and run ID `7de2c66970794080a7574a8f63e0e90f` returned one hit. The agent-side payload records score `70`, the domain `login.micros0ft-security.invalid` and the attachment SHA-256. The dashboard screenshot shows the alert summary. Its expanded IOC fields have not been captured. [Agent-side replay payload](evidence/agent-replay-2026-11-23.jsonl) · [Wazuh rule test screenshot](https://chatgpt.com/library?file_id=libfile_64cba0480060819195adcc4f2c6d75b2&account_id=personal) · [Dashboard screenshot](https://chatgpt.com/library?file_id=libfile_fb4dd7f4ae548191b7188c9d43d1bea5&account_id=personal)

## 2. Initial incident timeline

November 3 entries come from simulated email headers. The replay logs recorded UTC. The dashboard time is shown separately as displayed, consistent with Cairo time (UTC+02:00).

| When | Event | Evidence |
| --- | --- | --- |
| 2026-11-03 03:12:00 UTC | Date the simulated phishing message claims. | EML `Date` header |
| 2026-11-03 03:12:05 UTC | First recorded relay hop in the simulated trace. | First chronological `Received` entry |
| 2026-11-03 03:12:10 UTC | Final recorded hop to `mx.example.test` in the simulated trace. | Second chronological `Received` entry |
| 2026-11-23 19:15:38 UTC | Local replay and XML field validation completed for both samples. | Local replay and rule check |
| 2026-11-23 19:43:05 UTC | The Windows replay appended the phishing and benign events to the monitored file. | `depi_replayed_at` in the agent-side replay payload |
| 2026-11-23 21:43:05.958 (dashboard time) | Rule `110210` generated the level `10` alert from `win11_host`. | Wazuh Threat Hunting screenshot |

[Phishing email trace](../week_1/evidence/email/phish_001.eml.json) · [Replay events](evidence/local-replay.jsonl) · [Local rule check](evidence/local-rule-check.json)

## 3. Scope statement

The review covers the two synthetic EML reports, their email and attachment metadata, and the verified phishing alert from the Windows lab endpoint. The scenario contains one intended recipient and a simulated receiving mail host. Actual mailbox delivery, clicks, attachment execution, credential exposure, lateral spread, additional recipients and endpoint compromise remain unverified.

## 4. Affected users and assets

| User or asset | Role in the case | Evidence of impact |
| --- | --- | --- |
| `labuser@example.test` | Intended recipient in the synthetic email | Targeted in the simulation. No observed user interaction or account compromise. |
| `mx.example.test` | Receiving host in the synthetic `Received` trace | Represented in the simulated trace. No compromise evidence. |
| `win11_host` | Windows lab endpoint running the analyzer and Wazuh agent | The agent forwarded the phishing event to the manager. No compromise evidence. |

No user or asset is confirmed compromised in this test case.

## 5. Escalation recommendation

Keep this run in the lab investigation queue and route the high-risk result for analyst review. For a real case with the same signals, verify delivery and scope through mail logs and look for URL access, attachment opening or execution, and anomalous sign-ins. Escalate to incident response if corroborating evidence establishes user interaction, suspicious authentication, execution or wider exposure. The current simulation supports detection and triage evidence only.

## 6. Expanded ruleset validation

The native Wazuh 4.14.9 output matched the expected outcomes for all 11 fixtures. The test covers rule decisions on the manager. The original `110210` dashboard alert above is the available end-to-end evidence.

| Test event | Observed DEPI rule | Alert level |
| --- | --- | --- |
| High-risk phishing | `110210` | 10 |
| Medium risk with authentication signals only | `110211` | 7 |
| Low risk with SPF and DMARC failures | `110212` | 5 |
| Medium risk with a flagged link | `110213` | 8 |
| Medium risk with a flagged attachment | `110214` | 8 |
| Medium risk with a flagged link and attachment | `110215` | 9 |
| Medium risk with macro and link indicators | `110216` | 9 |
| Low risk with SPF failure alone | No DEPI alert | — |
| Benign replay | No DEPI alert | — |
| Unrelated source with high risk | No DEPI alert | — |
| Older medium-risk event without indicator fields | `110211` | 7 |

[Native Wazuh test output](https://chatgpt.com/library?file_id=libfile_867a529cc09c81919db195144cbfd067&account_id=personal) · [Test fixtures](../../wazuh/rule-test-events.jsonl)

## Live verification checklist

- [x] Prepare the Windows log collector configuration, JSONL replay tool and rule `110210`.
- [x] Save local phishing and benign events, and compare their expected rule outcomes.
- [x] Validate `110210` on the lab manager with `wazuh-logtest` for both samples.
- [x] Replay both events through the monitored log and verify the phishing alert arrived from `win11_host`.
- [x] Record the dashboard alert ID, agent, run ID and timestamp in the timeline and triage notes.
- [ ] Capture the expanded dashboard fields for the score, domain and attachment SHA-256. If the lab keeps JSON archives, check for the benign event there.
- [x] Install the expanded ruleset on the lab manager, validate it with `wazuh-analysisd -t`, and record native `wazuh-logtest` results for all 11 test events.

[Wazuh configuration and verification commands](../../wazuh/README.md)

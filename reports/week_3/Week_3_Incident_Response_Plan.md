# Week 3 - Containment, Eradication & Recovery

**DEPI Project 3 | Response plan and execution results**

The case is based on `sample-4091.eml`, a real email sample analyzed statically in the lab. The analyzer scored it **35 (medium)** based on recorded DMARC failure (+15) and a link whose displayed destination differs from its actual destination (+20). The email contains PDF and XML attachments. Their SHA-256 hashes are in the local analyzer report, and their maliciousness remains unverified. Delivery to an organizational mailbox, user interaction, credential exposure, attachment execution and endpoint compromise remain unverified.

The Windows replay under run ID `b7f674b4cce14972b23aed1b041695b3` generated Wazuh rule `110213` at level 8 at `2026-11-25 21:30:51.684` Cairo time. The indexed document contains score `35`, the source EML digest and the original Windows replay line. [Week 4 evidence register](../week_4/Chain_of_Custody.md)

## 1. Evidence preservation notes

Static reanalysis reproduced the findings in the saved analyzer report. The EML, full report and replay log are local Git-ignored evidence. Keep the originals and use copies for the exercise. Record the UTC collection time, collector, source, file location and SHA-256 for new exports. The replay digest covers the matching line encoded as UTF-8 without its line ending because the log is append-only. Keep full URLs, email addresses and attachment hashes in the local evidence and use redacted fields in shared screenshots.

| Evidence | SHA-256 |
| --- | --- |
| [Original EML](../../samples/phishing/sample-4091.eml) | `08e2f7723f802ca7fb8f4770051da410522385a23880ee57123051f181344ee2` |
| [Saved analyzer report](../generated/real-mail-alert-f15041da/sample-4091.eml.json) | `09b8cafa094a53127b61a94b5892ba7b60df33c00850932a17cef1a26afcd5ac` |
| [Windows replay log](../generated/wazuh-events.jsonl), matching run ID line | `169d5550cbe4f657edbcac07eb704de37e720b184b086b5bcc6157dd3d566bfe` |

## 2. Containment plan

| Timing | Trigger | Action and verification |
| --- | --- | --- |
| Short term | Suspicious link identified in `sample-4091.eml` | Preserve evidence and review the exact flagged destination in the local report. If a lab mail or filtering service is available, validate quarantine and an exact-match rule through an offline policy test or an inert stand-in. Use a benign control to check the policy scope. |
| Short term | Evidence of attachment execution or suspicious endpoint activity | Isolate the affected disposable lab endpoint. Record the action time and verify the isolation state. Use a tabletop exercise if no disposable endpoint is available. |
| Short term | Evidence of credential submission or suspicious sign-in | Lock the affected test account and revoke sessions. Verify that the account and existing sessions are blocked. Use a tabletop exercise if no test identity service is available. |
| Long term | After initial scope review | Search available test telemetry for the confirmed indicator. Review business impact before considering a broader domain block. Assign an owner and review date for any retained lab policy. |

## 3. Eradication checklist

- [x] Review the replay and Wazuh evidence. It supports detection of a suspicious link. Host compromise and credential exposure remain unverified.
- [ ] If execution is confirmed in a test scenario, preserve evidence, remove the identified malicious artifacts and persistence, and rescan. Use an inert test artifact for practical lab validation.
- [ ] Apply a patch if the investigation identifies an exploited vulnerability. Verify the installed version.
- [ ] Reset affected test credentials if exposure is indicated and verify the session revocation and fresh sign-in.
- [x] Remove the inert unwanted-artifact marker from the test mailbox and verify its absence.

## 4. Recovery plan

If a test host needs restoration, select a known-good lab snapshot or backup and verify the restored state. Verify health and Wazuh telemetry before releasing isolation. After restoration, check normal service and sign-in, replay the saved analyzer JSON for `sample-4091.eml` and the bundled benign control to verify detection behavior, and monitor for recurring indicator matches, unexpected processes and anomalous sign-ins. Use 24 hours as the proposed lab observation window and record the actual duration and findings. If the evidence supports no restoration, document that decision and verify the detection baseline.

## 5. Business impact assessment

| Area | Observed in the baseline | Potential impact and what to measure |
| --- | --- | --- |
| Users and accounts | Organizational delivery and user interaction remain unverified. | A locked account can interrupt work. Record the number of test accounts affected and lock duration if exercised. |
| Endpoints and services | The analysis event exists in the Windows replay log. Endpoint compromise remains unverified. | Isolation can interrupt endpoint or service access. Measure the duration and the services affected if exercised. |
| Data | Delivery, execution and data exposure remain unverified. | Record any evidence of access or disclosure and its scope. |
| Operations | Wazuh indexed the initial alert. The offline exercise quarantined one test copy and restored one test mailbox entry. | The scripted restore and immediate controls completed in 30 ms from the cleanup checkpoint. Production recovery time and service impact remain unmeasured. |

## 6. Lab execution results

Run `week3-response-v_1tckm4` started at `2026-11-25 20:07:42.158 UTC` in an isolated file-based mailbox. It exercised the actual analyzer and local file operations. The sample links and attachments stayed unopened.

| Check | Before | After |
| --- | --- | --- |
| Containment | A copy of `sample-4091.eml` was in the test inbox. | The copy was absent from the inbox and present in quarantine with the original SHA-256. |
| Eradication | An inert marker stood in for an unwanted artifact. | The marker was removed and its absence verified. |
| Recovery | A test mailbox entry differed from the clean backup. | The entry was restored and its SHA-256 matched the clean backup. |
| Post-recovery controls | Both samples were submitted as fresh copies. | The exact URL match routed `sample-4091.eml` to quarantine (score 35). `benign_001.eml` reached the inbox (score 0). |

Host isolation, account locks, patching, credential resets and VM restoration remain conditional on a scenario that supplies the relevant trigger and environment. The run verified immediate behavior. The proposed 24-hour monitoring window remains untested.

Reproduce from the repository root with `python -m tools.exercise_response`. The script prints the evidence path for each run. [Execution JSON](../generated/week3-response-v_1tckm4/execution.json) · [Runner](../../tools/exercise_response.py)

[NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

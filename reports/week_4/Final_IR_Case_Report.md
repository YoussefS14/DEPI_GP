# Final Incident Response Case Report

**DEPI Project 3 · Week 4 · 25 November 2026**  
**Case DEPI-4091 · Suspicious email · Detection verified in Wazuh**

## 1. Incident summary

The team analyzed the supplied email sample `sample-4091.eml` offline. The Python analyzer returned **35/100 (medium risk)**. The email recorded DMARC failure (+15), and the destination of a link differed from its displayed destination (+20). The message contained a PDF and an XML attachment. Static checks did not flag either attachment, and their maliciousness remains undetermined. The authentication results are the values recorded in the sample. The analyzer did not independently authenticate the message.

The Windows endpoint `win11_host` forwarded the analyzer replay to `wazuh-server`. Wazuh Threat Hunting showed exactly one hit for the sample run with **rule 110213, level 8**. The alert's expanded details showed score 35, the same run ID and the same message SHA-256 as the local evidence. This verifies the analyzer-to-SIEM path for the sample.

## 2. Timeline and scope

| UTC | Cairo (UTC+02:00) | Event | Evidence |
| --- | --- | --- | --- |
| 25 Nov 19:30:51 | 25 Nov 21:30:51 | The Windows lab log received the analyzer replay. | E03 |
| 25 Nov 19:30:51.684 | 25 Nov 21:30:51.684 | Wazuh generated the rule 110213 alert from agent 001, `win11_host`. | E04 |
| 25 Nov 19:55:18 | 25 Nov 21:55:18 | Week 4 preserved the EML, JSON report and replay record and registered six evidence items. | E01–E06 |
| 25 Nov 20:07:42 | 25 Nov 22:07:42 | The offline mailbox exercise verified quarantine, cleanup and restoration with positive and benign controls. | Week 3 execution JSON |
| 25 Nov 20:09:45 | 25 Nov 22:09:45 | The team preserved the Wazuh indexed alert from the JSON view and matched its raw log to the registered replay. | E07 |

The investigation covers one supplied EML, the Windows analyzer and replay, and the matching Wazuh alert. Organizational delivery, affected users, clicks, attachment execution, credential exposure and data loss remain unverified. The Windows agent was the replay source. Endpoint compromise remains unverified.

## 3. Analysis and triage

- **Disposition** — Suspicious email for analyst review. Medium is the analyzer's risk band. Level 8 is the Wazuh rule severity.
- **Alert correlation** — Run `b7f674b4cce14972b23aed1b041695b3`, index `wazuh-alerts-4.x-2026.11.25`, document `gncwFKIBkGtXUCDPp-2w`. The replay set URL `yes`, attachment `no`, and macro `no`. These fields satisfy the specialized medium-risk rule.
- **ATT&CK** — The analyzer mapped T1566.001 and T1566.002 from the message structure. The mappings describe potential delivery techniques. Attachment execution and link interaction remain unverified.
- **Forensics** — Logical file triage and a filtered live-process snapshot were collected. The snapshot covers the collector environment at collection time. Full RAM acquisition, disk imaging and endpoint compromise analysis were not performed because the case has no corroborated process execution or host compromise and no endpoint image was supplied.

## 4. Response and business impact

The Week 3 exercise moved a copy of `sample-4091.eml` into quarantine, removed an inert artifact, and restored an altered mailbox entry from a hash-verified clean backup. After recovery, the local policy quarantined the suspicious sample and allowed the benign control to reach the inbox. The exercise took place in an offline file-based mailbox. Organizational downtime, affected accounts and data loss remain unmeasured. [Week 3 execution results](../week_3/Week_3_Incident_Response_Plan.md#6-lab-execution-results)

## 5. Verification and demo

| Check | Result |
| --- | --- |
| Static reanalysis of `sample-4091.eml` | Fresh JSON matched the saved analyzer report field-for-field. Score 35. |
| Evidence integrity and correlation | E01-E07 matched their registered SHA-256 values. The indexed alert's `full_log` exactly matched the preserved replay record. |
| Positive SIEM result | One indexed hit for rule 110213, level 8, from `win11_host`. |
| Benign control | Bundled `benign_001.eml` scored 0 and reached the local test inbox after recovery. Week 2 native rule testing reported no DEPI alert. |
| Analyzer regression suite | 34 passed. The rerun used a writable temporary directory. |
| AI-assisted summary and QA | The executive summary and claims were checked against the preserved evidence, the expanded alert and the test outputs. Human sign-off remains pending. |

For a short demo, show score 35 and its two contributing signals from the local analysis, then show the benign score of 0. In Threat Hunting select an absolute range of **25 November 2026, 21:25–21:35 Cairo time**, and run:

```text
rule.id:110213 AND data.depi_run_id:"b7f674b4cce14972b23aed1b041695b3"
```

Open the result and show the agent, rule, risk score and message digest. Finish with the custody record and the decision to escalate only if additional telemetry shows user or host impact. The demo can use the existing alert without generating another replay.

## 6. Deliverables

- [Chain-of-custody form](Chain_of_Custody.md)
- [Forensic evidence summary](Forensic_Evidence_Summary.md)
- [Executive incident report](Executive_Incident_Report.md)
- [Mock lessons-learned review and action items](Lessons_Learned.md)
- [Updated incident response playbook](Updated_IR_Playbook.md)
- [Week 3 response plan](../week_3/Week_3_Incident_Response_Plan.md)

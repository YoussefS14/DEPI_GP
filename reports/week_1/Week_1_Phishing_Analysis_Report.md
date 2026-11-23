# Week 1 Phishing Analysis Report

**DEPI Project 3 — Phishing, Malware & End-to-End Incident Response Case**  
**Phase** Phishing & Initial Access Analysis

## Executive summary

The Python analyzer classified the simulated phishing email as **suspicious** with a **high risk score of 70**. The message impersonated support, threatened account suspension, and contained a link whose destination differed from the displayed address and an attachment with a `.pdf.exe` double extension. The benign comparison scored **0 (low)**. The evidence supports two simulated Initial Access techniques, T1566.001 and T1566.002. Execution and Defense Evasion were unobserved.

## 1. Scenario and method

The case models an email sent to a lab user under the display name `Microsoft Support`. The subject, `URGENT: Your account will be suspended`, asks the recipient to act quickly. The input set consists of four synthetic EML files and a separate synthetic VBA source fixture. The analyzer parsed the messages offline, inspected headers and HTML link destinations, and hashed attachment bytes. The link and attachment were left unopened. The VBA source was inspected separately as text, without execution.

| Email sample | Risk | Result |
| --- | --- | --- |
| [`phish_001.eml`](evidence/email/phish_001.eml.json) | 70, high | Suspicious link and attachment, header discrepancies, authentication failures and urgent wording. |
| [`benign_001.eml`](evidence/email/benign_001.eml.json) | 0, low | SPF, DKIM and DMARC recorded as `pass`. No suspicious links or attachments were reported. |
| [`incomplete_001.eml`](evidence/email/incomplete_001.eml.json) | 0, low | Authentication fields were `unknown`. Missing data limits what can be concluded. |
| [`malformed_001.eml`](evidence/email/malformed_001.eml.json) | 0, low | The parser completed and recorded `MissingHeaderBodySeparatorDefect`. The score has limited value for this message. |

The scores are heuristic. For the phishing sample, the analyzer assigned 10 points for SPF failure, 15 for DMARC failure, 20 for the flagged link, 20 for the flagged attachment and 5 for urgent wording.

## 2. Email header trace

| Header | Value | Interpretation |
| --- | --- | --- |
| `From` | `Microsoft Support <support@micros0ft-security.invalid>` | The display name claims Microsoft support and the domain spells `micros0ft` with a zero. |
| `To` | `labuser@example.test` | Synthetic lab recipient. |
| `Reply-To` | `collector@evil-reply.invalid` | Replies would go to a different domain from the `From` address. |
| `Return-Path` | `<bounce@random-host.invalid>` | Envelope return domain differs from the visible sender domain. |
| `Message-ID` | `<phish-001@random-host.invalid>` | Message ID shares the return-path domain and differs from the visible sender domain. |

The `Received` entries are listed oldest first. The timestamps below are in UTC as recorded in the original headers.

| Time on 3 November 2026 | Reported source | Receiving host |
| --- | --- | --- |
| `03:12:05 UTC` | `relay1.random-host.invalid` (`203.0.113.45`) | `mail.random-host.invalid` |
| `03:12:10 UTC` | `unknown`, with HELO `mail.random-host.invalid` (`198.51.100.23`) | `mx.example.test` |

| Authentication check | Recorded result | Header detail |
| --- | --- | --- |
| SPF | `fail` | `smtp.mailfrom=random-host.invalid` |
| DKIM | `none` | No `DKIM-Signature` header was present. |
| DMARC | `fail` | `header.from=micros0ft-security.invalid` |

These are values reported by `Authentication-Results` and `Received` in the synthetic message. The analyzer performed no independent DNS, signature or relay verification. The domain discrepancies were assessed alongside the link and attachment findings.

## 3. Extracted indicators of compromise

These indicators belong to the simulation. The CSV preserves the exact indicator values and their evidence fields. The URL is defanged below for readability. [IOC table (CSV)](evidence/iocs.csv)

| Type | Indicator | Source and relevance |
| --- | --- | --- |
| URL | `hxxp://login[.]micros0ft-security[.]invalid/verify?id=123` | HTML link destination. The analyzer detected a mismatch with the visible URL. |
| Destination domain | `login.micros0ft-security.invalid` | Host extracted from the flagged link. |
| Sender domain | `micros0ft-security.invalid` | `From` address uses a lookalike spelling. |
| Reply address | `collector@evil-reply.invalid` | `Reply-To` points to a different domain. |
| Relay IPs | `203.0.113.45`, `198.51.100.23` | Recorded in `Received`. These are synthetic trace values. |
| Attachment name | `Invoice_2026.pdf.exe` | A PDF-like name ends in `.exe`. The 33-byte attachment was declared `application/octet-stream` and the analyzer reported its detected type as `unknown`. |
| Attachment SHA-256 | `66ddbcdbad014d1370434d9109715a94eb2e8f478619d5b20b3afd605ec21c1b` | Hash of the attachment bytes in the simulated email. |

The source email SHA-256 is `a8b21afa7d23ca2a6773a245d329527bbe25574124d9ef3cdacf8e5703d0652b`. [Phishing sample JSON](evidence/email/phish_001.eml.json)

## 4. Malware behavior summary

The attachment scan found the double extension and recorded file metadata and a hash. The detected type is `unknown`, so the available evidence does not establish that the attachment is executable. The separate `demo_macro.bas` fixture contains an `AutoOpen` procedure whose body contains a message box and a comment. The static scanner flagged `AutoOpen`, `WScript.Shell`, `PowerShell` and `URLDownloadToFile` and assigned high heuristic risk. The last three keywords appear only in a comment. The fixture was analyzed as source and was not attached to the phishing sample. No process execution, download, or other malware behavior was observed. [Macro scan JSON](evidence/macro_analysis.json)

## 5. MITRE ATT&CK mapping

| Tactic | Technique | Assessment | Evidence |
| --- | --- | --- | --- |
| Initial Access | `T1566.001` — Spearphishing Attachment | Simulated, medium confidence | The simulated phishing message contained `Invoice_2026.pdf.exe` and the analyzer recorded its hash. |
| Initial Access | `T1566.002` — Spearphishing Link | Simulated, medium confidence | The visible link destination differed from the HTML link target. |
| Execution | `T1204.002` — User Execution: Malicious File | Unobserved | The email shows attachment delivery. No endpoint event records opening or execution. |
| Defense Evasion | No technique assigned | Unobserved | No evidence of an evasion action was present in the email or the static source scan. |

The Initial Access mappings came from the email-only run. The macro scan is documented independently. [Mapping evidence](evidence/email/phish_001.eml.json)

## 6. Validation and conclusion

The command-line analyzer generated reports for all four fixtures. The automated suite completed with **34 passed** and **19 warnings**. The simulated message has sufficient evidence for phishing triage and a simulated Initial Access mapping. The investigation recorded no confirmed payload execution, evasion or host compromise. [Test run output](pytest-results.txt)

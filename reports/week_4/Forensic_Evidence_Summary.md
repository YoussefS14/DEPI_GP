# Forensic Evidence Summary

**DEPI-4091 · 25 November 2026**

| Evidence | Finding | Scope |
| --- | --- | --- |
| E01 · Source EML | SHA-256 matched the replay and the alert. | The hash identifies the analyzed file. |
| E02 · Analyzer JSON | Risk 35. Recorded SPF unknown, DKIM none and DMARC fail. The link destination differed from its displayed destination. The analyzer recorded a PDF and an XML attachment and their digests. | Static inspection. Authentication is based on recorded headers. Attachment behavior and link interaction remain unverified. |
| E03 · Windows log extract | One replay line matched the case run ID. It recorded URL/attachment/macro flags as yes/no/no. | Evidence of the analyzer event on Windows. |
| E04 · Wazuh observation | One hit, rule 110213 at level 8, with risk score 35 from `win11_host` (001). | Selected fields were transcribed from the indexed alert. E07 preserves the complete indexed document. |
| E05 · Logical disk triage | Collected path, byte count, last-write timestamp and SHA-256 for the EML and analyzer JSON. | Case-file metadata only. The file timestamps do not establish delivery time. |
| E06 · Volatile triage | Four entries were visible under the process-name filter. The snapshot included PID and working-set size and was taken after the replay. | Collector environment only. The snapshot cannot establish what was running on a potentially affected endpoint during the event. |
| E07 – Indexed Wazuh JSON | Rule 110213, level 8, and the complete `full_log` matched E03. | Captured from the Discover JSON view. Covers the indexed alert for the original replay. |

No RAM image or disk image was available for examination. Where independent endpoint telemetry identifies suspected execution, preserve authorized volatile data from the affected lab host before shutdown if feasible, then collect relevant disk artifacts. Record the tool, time, source host, hash and custody handoff. For this case, retain static evidence and limit the conclusion to suspicious email detection.

The original email, full URLs, attachment hashes and source JSON are in the local evidence set. The [custody form](Chain_of_Custody.md) records acquisition and integrity. [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)

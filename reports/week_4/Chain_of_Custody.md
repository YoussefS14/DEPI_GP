# Chain-of-Custody Form

**Case** DEPI-4091  
**Collection time** 25 November 2026, 19:55:18 UTC  
**Collector** DEPI Week 4 automated collection and analyst dashboard observation  
**Storage** [Case evidence and manifest](../generated/week4-evidence-20261125T195518Z/manifest.json) in the local project evidence directory  
**Custodian acceptance** Pending project team signature

| ID | Collected artifact | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| E01 | `sample-4091.eml` | 78,033 | `08e2f7723f802ca7fb8f4770051da410522385a23880ee57123051f181344ee2` |
| E02 | `sample-4091.eml.json` | 10,349 | `09b8cafa094a53127b61a94b5892ba7b60df33c00850932a17cef1a26afcd5ac` |
| E03 | `sample-4091-replay-line.json` | 780 | `169d5550cbe4f657edbcac07eb704de37e720b184b086b5bcc6157dd3d566bfe` |
| E04 | `wazuh-alert-observation.json` | 562 | `d82978fb5cb42c2083a9127461b6b0b9b0396685a9f075914a7fc360f33155b9` |
| E05 | `case-file-system-triage.json` | 620 | `18f300fe7bdbbf299b473896df6be1cf102cd04bdb660df1690aae641d427224` |
| E06 | `filtered-live-processes.json` | 698 | `fbe30d7426798448bc9553ffb22d4fbad03f07a0886f678e534edd3985b1abac` |
| E07 | `wazuh-alert-native.json` | 2,364 | `386b5f1187fd63a29c46e5d585f4d5b4b2fff1367c34b0673c2eab7bb37e6d8a` |

- **E01 and E02** — Byte-for-byte copies of the supplied EML and saved analyzer JSON. The source and destination digests matched.
- **E03** — Exact bytes of the one matching Windows replay record, excluding the line ending. This scope excludes unrelated records added to the append-only log.
- **E04** - Manual transcription of selected expanded dashboard fields with the alert document ID.
- **E05** — Logical metadata and hashes for the two case files.
- **E06** — Time-stamped, filtered volatile process metadata from the collector environment.
- **E07** - Indexed document copied from the Wazuh Discover JSON view and saved as compact JSON. Its `full_log` text exactly matched E03.

## Custody events

| UTC | Evidence IDs | From | To | Purpose | Integrity / sign-off |
| --- | --- | --- | --- | --- | --- |
| 2026-11-25 19:55:18Z | E01–E06 | Original case files, replay log, dashboard and collector process list | Local evidence directory | Initial preservation and registration | SHA-256 recorded. Named custodian acceptance pending. |
| 2026-11-25 20:09:45Z | E07 | Wazuh Discover JSON view | Local evidence directory | Preserve indexed alert document | SHA-256 recorded. Raw event text matched E03. Named custodian acceptance pending. |

Further transfers recorded as of this report: zero. For each later handoff add UTC time, item ID, transferring custodian, receiving custodian, purpose, destination, SHA-256 verified by recipient and both signatures. Record redactions or exports as derived evidence with their own digest and the source item's ID.

| Transfer time (UTC) | Evidence IDs | Released by / signature | Received by / signature | Purpose and destination | Verified SHA-256 |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

# Lessons Learned and Action Items

**DEPI-4091 · 25 November 2026 · Mock tabletop review**

This was an AI-assisted walkthrough using analyst, SIEM engineer and response lead roles. The findings reflect the case evidence. Team attendance and approval remain pending.

| Review prompt | Tabletop finding | Decision |
| --- | --- | --- |
| How did the analyst confirm the alert belonged to the email? | The run ID and message digest matched across Windows and Wazuh. A narrow absolute time window displayed one hit. | Retain the run ID, message hash and time zone in the playbook. |
| What did the SIEM evidence establish? | The real sample reached Wazuh and matched rule 110213. The benign control's current result covers local scoring, and its native no-alert result comes from Week 2. | Capture positive and negative controls with the type of verification clearly identified. |
| What would trigger host or account action? | The available data shows a suspicious email. Delivery, interaction and execution evidence would change the response decision. | Require a recorded trigger and verify the action afterward. |
| What would make the evidence easier to review? | The exported custody record can be checked by hash. The indexed JSON and the replay matched. The collector process snapshot has limited scope. | Retain both records and practice endpoint acquisition on a disposable lab endpoint. |

## Action register

| Priority | Owner role | Due | Action | Completion evidence |
| --- | --- | --- | --- | --- |
| High | SIEM engineer | Completed | Preserve the complete indexed alert for the sample run. | E07 in the custody register. |
| High | Response lead | Completed | Execute and document the offline mailbox containment and recovery scenario. | Week 3 execution JSON and before-and-after results. |
| Medium | Forensics analyst | During the next disposable-VM exercise | Rehearse volatile capture and logical disk triage with inert artifacts. | Scoped acquisition record, hashes and findings. |
| Medium | Project lead | Before submission | Review the final package and assign names to owner roles and custody transfers. | Signed review and custody acceptance. |

AI assisted with summarization and QA. The QA checked the risk score, rule ID and level, Cairo/UTC conversion, evidence scope, and consistency between the technical and executive reports. [Updated IR playbook](Updated_IR_Playbook.md)

# Week 2 Wazuh integration

The replay tool converts saved Week 1 analyzer reports into single-line JSON events. It keeps the risk, verdict, sample provenance, authentication, IOC domains, attachment hashes and ATT&CK IDs. It exports flags for the URL, attachment and macro risk contributions already present in the analyzer report. The replay timestamp describes when the event was generated. The Windows agent forwards the events to the manager for evaluation.

| Rule | Alert level | Conditions for a DEPI replay event |
| --- | --- | --- |
| `110210` | 10 | Suspicious verdict and high analyzer risk (score 70 or above). |
| `110211` | 7 | Suspicious verdict and medium analyzer risk (score 30-69), with no specialized rule match. |
| `110212` | 5 | Inconclusive verdict, low analyzer risk and both SPF and DMARC recorded as `fail`. Review as an authentication signal. |
| `110213` | 8 | Medium risk with a flagged link and no flagged attachment or macro. |
| `110214` | 8 | Medium risk with a flagged attachment and no flagged link or macro. |
| `110215` | 9 | Medium risk with both a flagged link and attachment and no flagged macro. |
| `110216` | 9 | Medium risk with static macro indicators. |

Rules `110213`–`110216` specialize the medium-risk rule. The original high-risk rule retains ID `110210`, and its events now carry the three indicator fields. Replay older reports with the updated Python tool to include the fields. Older JSON events without those fields still use the generic medium-risk rule. The authentication rule uses the recorded email header results. A macro indicator means the analyzer flagged the static scan supplied for that analysis; the event does not establish that the macro was embedded or executed.

## 1. Configure the Windows agent

From the repository root, create the monitored log if it is missing. This command preserves any existing events.

```powershell
New-Item -ItemType Directory -Force reports/generated | Out-Null
if (-not (Test-Path reports/generated/wazuh-events.jsonl)) {
    New-Item -ItemType File reports/generated/wazuh-events.jsonl | Out-Null
}
```

In an administrator editor, add the block from [agent-localfile.xml](agent-localfile.xml) inside an existing `<ossec_config>` block in `C:\Program Files (x86)\ossec-agent\ossec.conf`. The supplied path matches `D:\repos\DEPI_GP`. Adjust the path and use the replay tool's `--log-file` option if the agent monitors a different location. In administrator PowerShell, run `Restart-Service -Name WazuhSvc`, the service registered on the project PC. If working on another PC, check the service name with `Get-Service -DisplayName '*Wazuh*'`. Confirm the agent is **Active** in the Wazuh dashboard before sending events.

## 2. Install and test the manager rule

On the manager, check that rule IDs `110210`–`110216` are available for this ruleset. Copy [depi_email_rules.xml](depi_email_rules.xml) to `/var/ossec/etc/rules/depi_email_rules.xml`, where the manager loads custom rules. Run `sudo /var/ossec/bin/wazuh-analysisd -t` to check the configuration.

To test both samples without adding events to the live log, run this from the Windows repository root. Use a new filename if repeating the preview because the tool appends events.

```powershell
python tools/replay_wazuh.py --log-file reports/generated/wazuh-preview.jsonl `
  reports/week_1/evidence/email/phish_001.eml.json `
  reports/week_1/evidence/email/benign_001.eml.json
Get-Content reports/generated/wazuh-preview.jsonl
```

On the manager, run `sudo /var/ossec/bin/wazuh-logtest` and paste the two JSON lines, one at a time. The phishing event should match rule `110210` at level `10`. The benign event should decode as JSON and should not match `110210`. After the checks, run `sudo systemctl restart wazuh-manager` to load the rule for live collection.

The [Week 2 evidence](../reports/week_2/evidence/local-replay.jsonl) already contains one line per sample for `wazuh-logtest`.

For an existing installation, update `/var/ossec/etc/rules/depi_email_rules.xml` with the current file, run `wazuh-analysisd -t`, and start a fresh `wazuh-logtest` session. Paste each line from [rule test events](rule-test-events.jsonl) and compare the results below before restarting the manager.

| Line | Scenario | Expected DEPI rule |
| --- | --- | --- |
| 1 | High-risk phishing replay | `110210`, level 10 |
| 2 | Medium risk with authentication signals only | `110211`, level 7 |
| 3 | Low risk with both SPF and DMARC failures | `110212`, level 5 |
| 4 | Medium risk with a flagged link | `110213`, level 8 |
| 5 | Medium risk with a flagged attachment | `110214`, level 8 |
| 6 | Medium risk with a flagged link and attachment | `110215`, level 9 |
| 7 | Medium risk with macro and link indicators | `110216`, level 9 |
| 8 | Low risk with SPF failure alone | No DEPI alert |
| 9 | Benign replay | No DEPI alert |
| 10 | Unrelated source with high risk | No DEPI alert |
| 11 | Older medium-risk event without indicator fields | `110211`, level 7 |

## 3. Replay through the agent

From the repository root, after the agent and manager are ready:

```powershell
python tools/replay_wazuh.py `
  reports/week_1/evidence/email/phish_001.eml.json `
  reports/week_1/evidence/email/benign_001.eml.json
```

In Wazuh Threat Hunting, filter by `rule.id:110210` and `data.depi_run_id` using the run ID printed by the tool. Look for the phishing report, sample provenance and risk score `70`. Save alert details with the timestamp and agent name under `reports/week_2/evidence/`. Save the benign `wazuh-logtest` result as comparison evidence. If JSON archives are already enabled on this lab manager, use the same run ID to find the benign event there and document receipt. The custom rule deliberately does not raise an alert for the benign event.

## Wazuh documentation

- [Monitoring log files](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html)
- [JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
- [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)

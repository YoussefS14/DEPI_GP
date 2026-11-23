# DEPI — Email Analyzer

Run from the repository root:

~~~powershell
python -m pip install -r requirements.txt
python main.py
python main.py email_analyzer/samples/phish_001.eml --output-dir reports/generated
python -m pytest
~~~

With no arguments, the CLI analyzes the bundled Week 1 fixtures. Pass one or
more local EML or TXT files to analyze other inputs. The report includes
headers, recorded authentication, attachment metadata and SHA-256 hashes,
IOCs, URL indicators, heuristic risk and MITRE ATT&CK mapping. Use
--macro-file with a single input to statically inspect an explicitly supplied
local file; embedded attachments are not opened or executed.

The active modules, tests and synthetic fixtures live under `email_analyzer/`.
The [sample inventory](email_analyzer/samples/sample_inventory.csv) lists the
four bundled emails. Running `python email_analyzer/make_samples.py` replaces
those files. Keep any private email inputs in the ignored `samples/` directory.

Authentication is reported as written in the message, not independently
verified. Risk and mapping are heuristic, not a malware verdict or proof of
execution. Keep reports private or redact sensitive fields before sharing.

- [Week 1 phishing analysis](reports/week_1/Week_1_Phishing_Analysis_Report.md)
- [Week 2 detection and triage](reports/week_2/Week_2_Detection_Triage_and_Scope.md)
- [Wazuh setup and validation](wazuh/README.md)

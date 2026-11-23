"""Append Wazuh JSON events from existing DEPI email analyzer reports."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = ROOT / "reports" / "generated" / "wazuh-events.jsonl"


def build_event(report, report_name, run_id):
    parsed = report["parsed"]
    if parsed["parse_errors"]:
        raise ValueError("the analyzer report contains parse errors")

    auth = (report["headers"] or {}).get("authentication", {})
    risk = report["risk"]
    reasons = risk.get("reasons", {})
    mitre = report["mitre"]
    iocs = report["iocs"]
    return {
        "depi_source": "depi_email_analyzer",
        "depi_event_type": "email_analysis_replay",
        "depi_run_id": run_id,
        "depi_replayed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "depi_report": report_name,
        "depi_message_sha256": parsed.get("message_sha256") or "unavailable",
        "depi_risk_score": risk["score"],
        "depi_risk_level": risk["level"],
        "depi_suspicious_url": "yes" if "suspicious_url" in reasons else "no",
        "depi_suspicious_attachment": "yes" if "suspicious_attachment" in reasons else "no",
        "depi_suspicious_macros": "yes" if "suspicious_macros" in reasons else "no",
        "depi_verdict": mitre["verdict"],
        "depi_provenance": mitre["provenance"],
        "depi_spf": auth.get("spf", "unknown"),
        "depi_dkim": auth.get("dkim", "unknown"),
        "depi_dmarc": auth.get("dmarc", "unknown"),
        "depi_domains": iocs["domains"],
        "depi_attachment_sha256": [
            attachment["sha256"] for attachment in iocs["sha256_embedded_attachments"]
        ],
        "depi_mitre_ids": [technique["technique_id"] for technique in mitre["mapped"]],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path, help="Email analyzer JSON reports")
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG, help="Wazuh-monitored JSONL log")
    args = parser.parse_args()
    run_id = uuid4().hex
    if any(path.resolve() == args.log_file.resolve() for path in args.reports):
        parser.error("the log file must be separate from the input reports")

    lines = []
    for path in args.reports:
        try:
            report = json.loads(path.read_text(encoding="utf-8-sig"))
            event = build_event(report, path.name, run_id)
            lines.append(json.dumps(event, separators=(",", ":")))
        except (OSError, KeyError, TypeError, AttributeError, ValueError) as error:
            parser.error(f"{path}: {error}")

    try:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        with args.log_file.open("a", encoding="utf-8", newline="\n") as log:
            log.write("\n".join(lines) + "\n")
    except OSError as error:
        parser.error(f"{args.log_file}: {error}")
    print(f"Appended {len(lines)} event(s) to {args.log_file}")
    print(f"Run ID: {run_id}")


if __name__ == "__main__":
    main()

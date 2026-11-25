"""Run the sample-4091 response exercise against an offline file-based mailbox."""

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from shutil import copyfile
from tempfile import mkdtemp

from email_analyzer.pipeline import analyze_sample
from tools.replay_wazuh import build_event


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/phishing/sample-4091.eml"
BENIGN = ROOT / "email_analyzer/samples/benign_001.eml"
OUTPUT = ROOT / "reports/generated"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def route_message(path, blocked_urls, inbox, quarantine, run_id):
    provenance = "simulated" if path.name == BENIGN.name else "observed"
    report = analyze_sample(path, provenance)
    event = build_event(report, path.name + ".json", run_id)
    matched = blocked_urls.intersection(report["iocs"]["urls"])
    destination = (quarantine if matched else inbox) / path.name
    require(not destination.exists(), "Destination already has a message with that name")
    path.rename(destination)
    require(digest(destination) == event["depi_message_sha256"], "Message changed during routing")
    return {
        "route": "quarantine" if matched else "inbox",
        "matched_urls": len(matched),
        "message_sha256": event["depi_message_sha256"],
        "risk_score": event["depi_risk_score"],
        "suspicious_url": event["depi_suspicious_url"],
    }


def main():
    source_report = analyze_sample(SAMPLE)
    require(not source_report["parsed"]["parse_errors"], "Source email parsing failed")
    blocked_urls = {item["url"] for item in source_report["urls"] if item["suspicious"]}
    require(blocked_urls and source_report["risk"]["score"] == 35, "Unexpected sample baseline")
    source_hash = digest(SAMPLE)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    lab = Path(mkdtemp(prefix="week3-response-", dir=OUTPUT))
    incoming, inbox, quarantine, backup = [lab / name for name in ("incoming", "inbox", "quarantine", "backup")]
    for folder in (incoming, inbox, quarantine, backup):
        folder.mkdir()

    started_at = utc_now()
    clean_backup = Path(copyfile(BENIGN, backup / BENIGN.name))
    clean_hash = digest(clean_backup)
    require(clean_hash == digest(BENIGN), "Backup did not match the benign source")
    baseline_path = Path(copyfile(SAMPLE, incoming / SAMPLE.name))
    baseline = route_message(baseline_path, set(), inbox, quarantine, lab.name)
    require(baseline["route"] == "inbox", "Baseline delivery failed")

    # Move the already-delivered copy, then exercise the filtering policy again after recovery.
    suspect_path = inbox / SAMPLE.name
    quarantined_copy = quarantine / SAMPLE.name
    require(blocked_urls.intersection(analyze_sample(suspect_path)["iocs"]["urls"]), "Containment IOC missing")
    suspect_path.rename(quarantined_copy)
    require(not suspect_path.exists() and digest(quarantined_copy) == source_hash, "Quarantine verification failed")
    contained_at = utc_now()

    # Stand-ins for an unwanted artifact and an altered mailbox entry in this disposable lab only.
    marker = inbox / "simulated-unwanted-artifact.txt"
    marker.write_text("Inert DEPI cleanup exercise marker\n", encoding="utf-8")
    marker_hash = digest(marker)
    affected_entry = inbox / BENIGN.name
    affected_entry.write_bytes(b"Simulated altered mailbox entry\n")
    altered_hash = digest(affected_entry)
    require(altered_hash != clean_hash, "Restore exercise did not start with an altered entry")
    marker.unlink()
    require(not marker.exists(), "Inert artifact remains after cleanup")
    eradicated_at = utc_now()

    copyfile(clean_backup, affected_entry)
    restored_hash = digest(affected_entry)
    require(restored_hash == clean_hash, "Restored mailbox entry differs from clean backup")
    post_inbox = inbox / "post-recovery"
    post_quarantine = quarantine / "post-recovery"
    post_inbox.mkdir()
    post_quarantine.mkdir()
    # Use the same policy and fresh copies to confirm both outcomes after the restore.
    positive = route_message(Path(copyfile(SAMPLE, incoming / SAMPLE.name)), blocked_urls,
                             post_inbox, post_quarantine, lab.name)
    negative = route_message(Path(copyfile(BENIGN, incoming / BENIGN.name)), blocked_urls,
                             post_inbox, post_quarantine, lab.name)
    require(positive["matched_urls"] > 0 and positive["risk_score"] == 35 and
            (post_quarantine / SAMPLE.name).is_file() and not (post_inbox / SAMPLE.name).exists(),
            "Suspicious sample passed the active policy")
    require(negative["matched_urls"] == 0 and negative["risk_score"] == 0 and
            (post_inbox / BENIGN.name).is_file() and not (post_quarantine / BENIGN.name).exists(),
            "Benign control failed the active policy")
    require(digest(SAMPLE) == source_hash, "Original sample changed during exercise")

    evidence = {
        "run": lab.name,
        "scope": "Offline file-based lab mailbox; local metadata and file operations only",
        "started_utc": started_at,
        "containment": {"before": baseline, "after": "quarantine", "quarantined_sha256": source_hash,
                        "completed_utc": contained_at},
        "eradication": {"inert_marker_sha256": marker_hash, "marker_removed": True,
                        "completed_utc": eradicated_at},
        "recovery": {"altered_sha256": altered_hash, "backup_sha256": clean_hash,
                     "restored_sha256": restored_hash, "positive": positive, "benign": negative,
                     "completed_utc": utc_now()},
        "source_unchanged": True,
    }
    evidence_path = lab / "execution.json"
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(evidence_path.relative_to(ROOT))


if __name__ == "__main__":
    main()

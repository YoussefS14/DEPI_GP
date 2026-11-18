"""MITRE ATT&CK mapping (task W1_12).

Maps only what the evidence supports. Static email analysis can show phishing
delivery, but it cannot show user execution, so execution techniques stay
unmapped until real endpoint evidence (Sysmon or Wazuh events from Week 2)
is supplied through execution_observed.

Every mapped entry carries: technique ID and name, tactic, status
(observed, simulated or discussed), confidence, evidence, source artifact
and a short rationale. Anything not mapped is listed with the reason, so
the final report can show what was considered and why it was left out.

Verify technique IDs and names against https://attack.mitre.org/ before
the final report, because ATT&CK is updated regularly.
"""

H = chr(45)

SUSPECT = ("suspicious", "malicious")
PROVENANCE = ("observed", "simulated", "discussed")

# Extension to expected file signature label (see email_parser.SIGNATURES).
EXPECTED_TYPE = {
    ".pdf": "pdf",
    ".exe": "windows_executable",
    ".dll": "windows_executable",
    ".zip": "zip_or_ooxml",
    ".docx": "zip_or_ooxml",
    ".xlsx": "zip_or_ooxml",
    ".pptx": "zip_or_ooxml",
    ".doc": "ole2_office",
    ".xls": "ole2_office",
    ".ppt": "ole2_office",
    ".rar": "rar",
    ".gz": "gzip",
    ".rtf": "rtf",
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
}


def _entry(tid, name, tactic, status, confidence, evidence, source, rationale):
    return {
        "technique_id": tid,
        "name": name,
        "tactic": tactic,
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
        "source": source,
        "rationale": rationale,
    }


def _skip(tid, reason, area=None):
    return {"technique_id": tid, "area": area, "reason": reason}


def _confidence(count):
    """low for 1 evidence item, medium for 2 or 3, high for 4 or more."""
    if count >= 4:
        return "high"
    if count >= 2:
        return "medium"
    return "low"


def _type_mismatch(att):
    expected = EXPECTED_TYPE.get(att.get("extension"))
    detected = att.get("detected_type")
    return bool(expected and detected not in (None, "unknown", expected))


def _why_not(has_item, label, verdict):
    if not has_item:
        return "no " + label + " in this sample"
    return "verdict is " + verdict + ", below the suspicious threshold"


def map_attack(parsed, headers_result=None, url_findings=None, macro_result=None,
               verdict="inconclusive", provenance="simulated",
               execution_observed=False):
    """Return {"mapped": [...], "not_mapped": [...]} for one analyzed sample.

    parsed: dict from email_parser.parse_eml
    headers_result: dict from header_analyzer.analyze_headers (optional)
    url_findings: list of dicts with url, suspicious (bool), reasons (list)
    macro_result: dict with has_macros (bool) from the macro analyzer
    verdict: benign, suspicious, malicious or inconclusive
    provenance: observed, simulated or discussed (is this a real sample or a test)
    execution_observed: True only when endpoint evidence shows the user ran it
    """
    if provenance not in PROVENANCE:
        raise ValueError("provenance must be one of " + ", ".join(PROVENANCE))

    headers_result = headers_result or {}
    url_findings = url_findings or []
    macro_result = macro_result or {}
    attachments = parsed.get("attachments", [])
    bad_urls = [u for u in url_findings if u.get("suspicious")]
    suspect = verdict in SUSPECT

    mapped = []
    not_mapped = []
    sub_mapped = False

    # T1566.001 Spearphishing Attachment
    if suspect and attachments:
        evidence = []
        mismatch = False
        for att in attachments:
            evidence.append(
                "filename=" + str(att.get("filename"))
                + " detected_type=" + str(att.get("detected_type"))
                + " sha256=" + str(att.get("sha256"))
            )
            if _type_mismatch(att):
                mismatch = True
                evidence.append(
                    "extension " + str(att.get("extension"))
                    + " does not match file signature "
                    + str(att.get("detected_type"))
                )
        has_macros = bool(macro_result.get("has_macros"))
        if has_macros:
            evidence.append("macro present (static inspection, not executed)")
        confidence = "high" if (mismatch or has_macros) else "medium"
        mapped.append(_entry(
            "T1566.001", "Phishing: Spearphishing Attachment", "Initial Access",
            provenance, confidence, evidence, "email_parser.attachments",
            "Suspicious message delivered with an attachment."))
        sub_mapped = True
    else:
        not_mapped.append(_skip(
            "T1566.001", _why_not(bool(attachments), "attachment", verdict)))

    # T1566.002 Spearphishing Link
    if suspect and bad_urls:
        evidence = []
        strong = False
        for u in bad_urls:
            reasons = u.get("reasons", [])
            evidence.append(
                "url=" + str(u.get("url")) + " reasons=" + ", ".join(reasons))
            if len(reasons) >= 2:
                strong = True
        mapped.append(_entry(
            "T1566.002", "Phishing: Spearphishing Link", "Initial Access",
            provenance, "high" if strong else "medium", evidence,
            "url_analyzer.findings",
            "Suspicious message containing links flagged as suspicious."))
        sub_mapped = True
    else:
        not_mapped.append(_skip(
            "T1566.002", _why_not(bool(bad_urls), "suspicious link", verdict)))

    # T1566 parent, only when no sub technique fits better
    if suspect and not sub_mapped:
        evidence = [
            f.get("id", "") + ": " + f.get("detail", "")
            for f in headers_result.get("findings", [])
            if f.get("kind") == "heuristic"
        ]
        if evidence:
            mapped.append(_entry(
                "T1566", "Phishing", "Initial Access", provenance,
                _confidence(len(evidence)), evidence,
                "header_analyzer.findings",
                "Suspicious message with no attachment or link evidence, "
                "mapped at the parent technique level."))
        else:
            not_mapped.append(_skip(
                "T1566", "verdict is " + verdict + " but no recorded evidence to cite"))
    elif suspect:
        not_mapped.append(_skip(
            "T1566", "mapped at the sub technique level instead"))
    else:
        not_mapped.append(_skip("T1566", "verdict is " + verdict))

    # T1204.002 User Execution: Malicious File
    if execution_observed:
        mapped.append(_entry(
            "T1204.002", "User Execution: Malicious File", "Execution",
            provenance, "medium",
            ["execution evidence supplied by the analyst (Sysmon or Wazuh event)"],
            "endpoint telemetry",
            "Endpoint telemetry shows the delivered file was run. "
            "Replace the evidence line with the exact event ID and timestamp."))
    else:
        reason = ("static email analysis shows delivery, not execution; "
                  "map after endpoint evidence exists")
        if macro_result.get("has_macros"):
            reason += ("; macro presence is a capability, "
                       "not an observed behavior")
        not_mapped.append(_skip("T1204.002", reason))

    # Defense Evasion
    not_mapped.append(_skip(
        None, "no specific evasion behavior observed", area="Defense Evasion"))

    return {
        "verdict": verdict,
        "provenance": provenance,
        "mapped": mapped,
        "not_mapped": not_mapped,
    }


def to_markdown(result):
    """Render the mapping as a markdown table plus a list of what was not mapped."""
    cols = ["Technique", "Name", "Tactic", "Status", "Confidence",
            "Evidence", "Source"]
    lines = ["| " + " | ".join(cols) + " |",
             "|" + "|".join([H * 3] * len(cols)) + "|"]
    for m in result["mapped"]:
        lines.append("| " + " | ".join([
            m["technique_id"], m["name"], m["tactic"], m["status"],
            m["confidence"], "; ".join(m["evidence"]), m["source"],
        ]) + " |")
    lines.append("")
    lines.append("Not mapped:")
    for n in result["not_mapped"]:
        label = n["technique_id"] or n["area"]
        lines.append("* " + str(label) + ": " + n["reason"])
    return "\n".join(lines)

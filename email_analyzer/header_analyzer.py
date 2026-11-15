"""Header analysis: extracts facts and flags heuristic indicators with evidence."""
import re
from email.utils import parseaddr, parsedate_to_datetime

from email_parser import hdr

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REQUIRED = ["From", "Date", "Subject", hdr("Message", "ID")]


def _address(value):
    return parseaddr(value or "")


def _domain(value):
    addr = _address(value)[1]
    if "@" in addr:
        return addr.rsplit("@", 1)[1].lower().strip("<> ")
    return None


def parse_received(line):
    """Pull sender host, receiving host, IPs and timestamp out of one Received line."""
    m_from = re.search(r"\bfrom\s+(\S+)", line, re.I)
    m_by = re.search(r"\bby\s+(\S+)", line, re.I)
    stamp = line.rsplit(";", 1)[1].strip() if ";" in line else None
    parsed_time = None
    if stamp:
        try:
            parsed_time = parsedate_to_datetime(stamp).isoformat()
        except Exception:
            parsed_time = None
    return {
        "from_host": m_from.group(1) if m_from else None,
        "by_host": m_by.group(1) if m_by else None,
        "ips": IP_RE.findall(line),
        "timestamp_raw": stamp,
        "timestamp": parsed_time,
        "raw": " ".join(line.split()),
    }


def _finding(fid, kind, severity, detail, evidence):
    return {"id": fid, "kind": kind, "severity": severity,
            "detail": detail, "evidence": evidence}


def analyze_headers(parsed):
    """Takes the dict from parse_eml. kind is observed (fact) or heuristic (indicator)."""
    h = parsed.get("headers", {})
    findings = []

    # 1. Missing headers (observed fact)
    for name in REQUIRED:
        if not h.get(name):
            findings.append(_finding("missing_header", "observed", "low",
                                     name + " header is missing", {"header": name}))

    # 2. Sender identity checks
    from_name, from_addr = _address(h.get("From"))
    from_dom = _domain(h.get("From"))
    reply_dom = _domain(h.get(hdr("Reply", "To")))
    return_dom = _domain(h.get(hdr("Return", "Path")))
    msgid_dom = _domain(h.get(hdr("Message", "ID")))

    if from_dom and reply_dom and from_dom != reply_dom:
        findings.append(_finding(
            "reply_to_mismatch", "heuristic", "medium",
            "Reply domain differs from From domain",
            {"from": from_dom, "reply_to": reply_dom}))

    if from_dom and return_dom and from_dom != return_dom:
        findings.append(_finding(
            "return_path_mismatch", "heuristic", "low",
            "Return path domain differs from From domain (mailing lists do this legitimately)",
            {"from": from_dom, "return_path": return_dom}))

    if from_dom and msgid_dom and from_dom != msgid_dom:
        findings.append(_finding(
            "message_id_domain_mismatch", "heuristic", "low",
            "Message ID domain differs from From domain",
            {"from": from_dom, "message_id": msgid_dom}))

    if "@" in (from_name or ""):
        name_dom = from_name.rsplit("@", 1)[1].lower().strip("<> ")
        if from_dom and name_dom != from_dom:
            findings.append(_finding(
                "display_name_spoof", "heuristic", "medium",
                "Display name contains an address on a different domain",
                {"display_name": from_name, "actual": from_addr}))

    # 3. Received chain (top header is the most recent hop, so reverse it)
    hops = [parse_received(r) for r in reversed(parsed.get("received", []))]
    if not hops:
        findings.append(_finding("no_received", "observed", "low",
                                 "No Received headers found", {}))

    times = [x["timestamp"] for x in hops if x["timestamp"]]
    if times != sorted(times):
        findings.append(_finding(
            "received_time_order", "heuristic", "low",
            "Received timestamps are not in chronological order", {"timestamps": times}))

    # 4. Date header
    date_raw = h.get("Date")
    if date_raw:
        try:
            parsedate_to_datetime(date_raw)
        except Exception:
            findings.append(_finding("bad_date", "observed", "low",
                                     "Date header could not be parsed", {"date": date_raw}))

    return {
        "sender": {"display_name": from_name, "address": from_addr, "domain": from_dom},
        "reply_to_domain": reply_dom,
        "return_path_domain": return_dom,
        "message_id_domain": msgid_dom,
        "authentication_results_raw": h.get(hdr("Authentication", "Results")),
        "hop_count": len(hops),
        "hops": hops,
        "findings": findings,
    }
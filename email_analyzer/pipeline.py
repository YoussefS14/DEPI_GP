import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from .analysis_modules import analyze_macros, extract_iocs, score_risk
from .email_parser import parse_eml
from .header_analyzer import analyze_headers
from .mitre_mapper import EXPECTED_TYPE, map_attack


SAMPLES = Path(__file__).resolve().parent / "samples"
REVIEW_EXTENSIONS = {".exe", ".dll", ".scr", ".lnk", ".js", ".vbs", ".ps1", ".docm", ".xlsm", ".pptm"}


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.mismatches = set()
        self.href = None
        self.label = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.handle_endtag("a")
            self.href = (dict(attrs).get("href") or "").strip()
            if host(self.href):
                self.links.add(self.href)

    def handle_data(self, data):
        if self.href:
            self.label.append(data)

    def handle_endtag(self, tag):
        if tag == "a":
            destination = host(self.href or "")
            visible = host("".join(self.label).strip())
            if destination and visible and destination != visible:
                self.mismatches.add(self.href)
            self.href = None
            self.label = []


def host(url):
    try:
        parsed = urlsplit(url)
        return parsed.hostname if parsed.scheme.lower() in {"http", "https"} else None
    except ValueError:
        return None


def read_input(path):
    path = Path(path)
    if path.suffix.lower() != ".eml":
        return path.read_text(encoding="utf-8")
    parsed = parse_eml(path)
    if parsed["message_sha256"] is None:
        raise ValueError("; ".join(parsed["parse_errors"]))
    return "\n".join((parsed["text_body"], parsed["html_body"]))


def analyze_sample(path, provenance="observed", macro_path=None):
    path = Path(path)
    if path.suffix.lower() == ".eml":
        parsed = parse_eml(path)
        headers = analyze_headers(parsed) if parsed["headers"] else None
        text = parsed.pop("text_body")
        html = parsed.pop("html_body")
    else:
        text = read_input(path)
        html = ""
        parsed = {"file": str(path), "attachments": [], "parse_errors": [], "defects": []}
        headers = None

    links = LinkCollector()
    links.feed(html)
    links.close()
    links.handle_endtag("a")
    iocs = extract_iocs("\n".join((text, *sorted(links.links))))
    urls = []
    for url in iocs["urls"]:
        reasons = []
        destination = host(url)
        if destination in iocs["ips"]:
            reasons.append("ip_destination")
        if destination and any(label.startswith("xn--") for label in destination.split(".")):
            reasons.append("punycode_destination")
        if url in links.mismatches:
            reasons.append("visible_destination_mismatch")
        urls.append({"url": url, "suspicious": bool(reasons), "reasons": reasons})

    attachments = parsed["attachments"]
    iocs["sha256_embedded_attachments"] = [
        {"filename": item["filename"], "sha256": item["sha256"]} for item in attachments
    ]
    macro = analyze_macros(macro_path) if macro_path else None
    auth = (headers or {}).get("authentication", {})
    risk = score_risk(
        **{f"{method}_fail": auth.get(method) == "fail" for method in ("spf", "dkim", "dmarc")},
        suspicious_url=any(item["suspicious"] for item in urls),
        suspicious_attachment=any(
            item["extension"] in REVIEW_EXTENSIONS
            or (item["extension"] in EXPECTED_TYPE and item["detected_type"] not in
                {"unknown", EXPECTED_TYPE[item["extension"]]})
            for item in attachments
        ),
        suspicious_macros=bool(macro and macro["risk"] == "high"),
        urgent_language=bool(re.search(r"\b(urgent|immediately|verify now)\b", text, re.I)),
    )
    verdict = "suspicious" if risk["level"] in {"medium", "high"} else "inconclusive"
    mapping = map_attack(parsed, headers, urls, macro, verdict=verdict, provenance=provenance)
    return {"parsed": parsed, "headers": headers, "iocs": iocs, "urls": urls,
            "macros": macro, "risk": risk, "mitre": mapping}

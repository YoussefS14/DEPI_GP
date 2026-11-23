import re
import hashlib
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

SUSPICIOUS_MACRO_TERMS = ('AutoOpen', 'Document_Open', 'Workbook_Open', 'CreateObject', 'Shell(', 'WScript.Shell', 'PowerShell', 'URLDownloadToFile')

def analyze_macros(file_path):
    """Analyze Office VBA macros with oletools (pip install oletools). Never execute macros."""
    results = {'file': str(file_path), 'has_macros': None, 'indicators': [], 'risk': 'unknown', 'status': 'error'}
    parser = None
    try:
        from oletools.olevba import VBA_Parser
        parser = VBA_Parser(str(file_path))
        results['has_macros'] = bool(parser.detect_vba_macros())
        results['status'] = 'ok'
        results['risk'] = 'low'
        if results['has_macros']:
            for _, _, name, code in parser.extract_macros():
                for term in SUSPICIOUS_MACRO_TERMS:
                    if term.lower() in code.lower():
                        results['indicators'].append({'module': name, 'keyword': term})
            results['risk'] = 'high' if results['indicators'] else 'medium'
    except Exception as exc:
        results.update(status='error', has_macros=None, risk='unknown', error=str(exc))
    finally:
        if parser is not None:
            parser.close()
    return results

def extract_iocs(text, attachment_paths=()):
    """Extract and deduplicate common IOCs without contacting external hosts."""
    urls = sorted(set(re.findall(r'https?://[^\s<>"\']+', text, flags=re.I)))
    urls = [u.rstrip('.,);]') for u in urls]
    ips = set()
    for candidate in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text):
        try:
            ipaddress.IPv4Address(candidate)
            ips.add(candidate)
        except ipaddress.AddressValueError:
            pass
    domains = set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text))
    for url in urls:
        try:
            hostname = urlparse(url).hostname
        except ValueError:
            continue
        if hostname:
            domains.add(hostname)
    domains = {d.lower() for d in domains}
    domains.difference_update(ips)
    hashes = {}
    for path in attachment_paths:
        p = Path(path)
        if p.is_file():
            h = hashlib.sha256()
            with p.open('rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            hashes[str(p)] = h.hexdigest()
        else:
            raise FileNotFoundError(str(p))
    emails = sorted(set(re.findall(r'[a-zA-Z0-9_.+%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)))
    return {'urls': sorted(set(urls)), 'domains': sorted(domains), 'ips': sorted(ips),
            'emails': emails, 'sha256_attachments': hashes}

def score_risk(*, spf_fail=False, dkim_fail=False, dmarc_fail=False, suspicious_url=False,
               suspicious_attachment=False, suspicious_macros=False, urgent_language=False):
    """Heuristic triage score, not a validated malware verdict."""
    weights = {'spf_fail': 10, 'dkim_fail': 10, 'dmarc_fail': 15, 'suspicious_url': 20,
               'suspicious_attachment': 20, 'suspicious_macros': 20, 'urgent_language': 5}
    flags = locals().copy()
    contributions = {k: weight for k, weight in weights.items() if flags[k]}
    score = min(100, sum(contributions.values()))
    level = 'high' if score >= 70 else 'medium' if score >= 30 else 'low'
    return {'score': score, 'level': level, 'reasons': contributions}

if __name__ == '__main__':
    sample = 'Please verify at https://example.org/login from 192.0.2.10 immediately.'
    print('IOCs:', extract_iocs(sample))
    print('Risk:', score_risk(dmarc_fail=True, suspicious_url=True, urgent_language=True))

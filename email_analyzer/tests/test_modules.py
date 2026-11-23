import hashlib
import tempfile
import unittest
from pathlib import Path
from email_analyzer.analysis_modules import analyze_macros, extract_iocs, score_risk
from main import read_input

class AnalysisTests(unittest.TestCase):
    def test_ioc_validation_and_duplicates(self):
        result = extract_iocs('https://example.org/a https://example.org/a. 192.0.2.10 999.1.1.1 training@example.org')
        self.assertEqual(result['urls'], ['https://example.org/a'])
        self.assertEqual(result['ips'], ['192.0.2.10'])
        self.assertEqual(result['emails'], ['training@example.org'])
    def test_hash_and_same_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp)/'a'/'file.txt', Path(tmp)/'b'/'file.txt']
            for p in paths:
                p.parent.mkdir(); p.write_bytes(b'hello')
            result = extract_iocs('', paths)['sha256_attachments']
            self.assertEqual(len(result), 2)
            self.assertEqual(result[str(paths[0])], hashlib.sha256(b'hello').hexdigest())
    def test_missing_attachment_is_error(self):
        with self.assertRaises(FileNotFoundError):
            extract_iocs('', ['nonexistent_attachment.bin'])
    def test_risk_boundaries(self):
        self.assertEqual(score_risk()['score'], 0)
        self.assertEqual(score_risk(spf_fail=True, suspicious_url=True)['level'], 'medium')
        self.assertEqual(score_risk(dmarc_fail=True, suspicious_url=True, suspicious_attachment=True, suspicious_macros=True)['level'], 'high')
    def test_risk_maximum_and_reasons(self):
        r = score_risk(spf_fail=True, dkim_fail=True, dmarc_fail=True, suspicious_url=True, suspicious_attachment=True, suspicious_macros=True, urgent_language=True)
        self.assertEqual(r['score'], 100)
        self.assertEqual(sum(r['reasons'].values()), 100)
    def test_macro_error_not_clean(self):
        r = analyze_macros('missing.docm')
        self.assertEqual(r['status'], 'error')
        self.assertIsNone(r['has_macros'])
        self.assertEqual(r['risk'], 'unknown')
    def test_inert_macro_source(self):
        r = analyze_macros(Path(__file__).resolve().parents[1]/'samples'/'demo_macro.bas')
        self.assertEqual(r['status'], 'ok')
        self.assertTrue(r['has_macros'])
        self.assertTrue(r['indicators'])
    def test_mime_decoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'test.eml'
            p.write_bytes(b'From: a@example.org\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\naHR0cHM6Ly9leGFtcGxlLm9yZw==')
            self.assertIn('https://example.org', read_input(p))

if __name__ == '__main__':
    unittest.main()

from email_analyzer.pipeline import SAMPLES, analyze_sample


def test_week_one_samples_use_current_pipeline():
    clean = analyze_sample(SAMPLES / "benign_001.eml", provenance="simulated")
    assert clean["headers"]["authentication"] == dict.fromkeys(("spf", "dkim", "dmarc"), "pass")
    assert clean["risk"]["level"] == "low"

    suspicious = analyze_sample(SAMPLES / "phish_001.eml", provenance="simulated")
    assert suspicious["risk"]["level"] == "high"
    assert suspicious["headers"]["hops"][0]["ips"] == ["203.0.113.45"]
    assert len(suspicious["iocs"]["sha256_embedded_attachments"][0]["sha256"]) == 64
    assert {item["technique_id"] for item in suspicious["mitre"]["mapped"]} == {"T1566.001", "T1566.002"}
    assert "text_body" not in suspicious["parsed"]

    incomplete = analyze_sample(SAMPLES / "incomplete_001.eml")
    assert incomplete["headers"]["authentication"] == dict.fromkeys(("spf", "dkim", "dmarc"), "unknown")
    malformed = analyze_sample(SAMPLES / "malformed_001.eml")
    assert malformed["parsed"]["defects"]


def test_malformed_url_does_not_abort_analysis(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("https://[bad.invalid/ and https://example.test/", encoding="utf-8")
    report = analyze_sample(sample)
    assert "example.test" in report["iocs"]["domains"]

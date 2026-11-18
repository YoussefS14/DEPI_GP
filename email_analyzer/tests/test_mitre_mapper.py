import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mitre_mapper import map_attack, to_markdown


def att(name="invoice.pdf", ext=".pdf", detected="pdf"):
    return {
        "filename": name,
        "extension": ext,
        "detected_type": detected,
        "sha256": "abc123",
    }


def ids(result):
    return [m["technique_id"] for m in result["mapped"]]


def test_benign_maps_nothing():
    r = map_attack({"attachments": [att()]}, verdict="benign")
    assert r["mapped"] == []
    assert r["not_mapped"]


def test_inconclusive_maps_nothing():
    r = map_attack({"attachments": [att()]}, verdict="inconclusive")
    assert r["mapped"] == []


def test_suspicious_attachment_maps_sub_technique_not_parent():
    r = map_attack({"attachments": [att()]}, verdict="suspicious")
    assert ids(r) == ["T1566.001"]
    assert r["mapped"][0]["confidence"] == "medium"


def test_type_mismatch_raises_confidence():
    bad = att(detected="windows_executable")
    r = map_attack({"attachments": [bad]}, verdict="suspicious")
    assert r["mapped"][0]["confidence"] == "high"
    assert any("does not match" in e for e in r["mapped"][0]["evidence"])


def test_suspicious_link_maps_t1566_002():
    urls = [{"url": "http://example.invalid/x", "suspicious": True,
             "reasons": ["ip host", "login keyword"]}]
    r = map_attack({"attachments": []}, url_findings=urls, verdict="suspicious")
    assert ids(r) == ["T1566.002"]
    assert r["mapped"][0]["confidence"] == "high"


def test_non_suspicious_link_is_not_mapped():
    urls = [{"url": "http://example.invalid/x", "suspicious": False}]
    r = map_attack({"attachments": []}, url_findings=urls, verdict="suspicious")
    assert "T1566.002" not in ids(r)


def test_parent_used_only_when_no_sub_technique_fits():
    hdr_result = {"findings": [
        {"id": "reply_to_mismatch", "kind": "heuristic", "detail": "mismatch"},
    ]}
    r = map_attack({"attachments": []}, headers_result=hdr_result,
                   verdict="suspicious")
    assert ids(r) == ["T1566"]


def test_execution_not_mapped_without_endpoint_evidence():
    r = map_attack({"attachments": [att()]}, verdict="malicious",
                   macro_result={"has_macros": True})
    assert "T1204.002" not in ids(r)
    reasons = [n["reason"] for n in r["not_mapped"]
               if n["technique_id"] == "T1204.002"]
    assert reasons and "capability" in reasons[0]


def test_execution_mapped_when_endpoint_evidence_supplied():
    r = map_attack({"attachments": [att()]}, verdict="malicious",
                   execution_observed=True)
    assert "T1204.002" in ids(r)


def test_provenance_is_recorded_and_validated():
    r = map_attack({"attachments": [att()]}, verdict="suspicious",
                   provenance="observed")
    assert r["mapped"][0]["status"] == "observed"
    with pytest.raises(ValueError):
        map_attack({}, provenance="guessed")


def test_markdown_output_has_table_and_not_mapped_list():
    r = map_attack({"attachments": [att()]}, verdict="suspicious")
    text = to_markdown(r)
    assert "T1566.001" in text
    assert "Not mapped:" in text

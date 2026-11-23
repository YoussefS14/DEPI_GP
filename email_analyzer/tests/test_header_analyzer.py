from email_analyzer.email_parser import hdr
from email_analyzer.header_analyzer import analyze_headers, parse_received


def base():
    return {
        "headers": {
            "From": "Alice <alice@example.invalid>",
            "Date": "Mon, 05 Oct 2026 10:00:00 +0000",
            "Subject": "Hi",
            hdr("Message", "ID"): "<abc@example.invalid>",
        },
        "received": [],
    }


def ids(result):
    return [f["id"] for f in result["findings"]]


def test_clean_headers_have_no_identity_findings():
    r = analyze_headers(base())
    assert "reply_to_mismatch" not in ids(r)
    assert "message_id_domain_mismatch" not in ids(r)
    assert "display_name_spoof" not in ids(r)


def test_reply_to_mismatch_flagged_with_evidence():
    p = base()
    p["headers"][hdr("Reply", "To")] = "x@other.invalid"
    r = analyze_headers(p)
    f = [f for f in r["findings"] if f["id"] == "reply_to_mismatch"][0]
    assert f["kind"] == "heuristic"
    assert f["evidence"]["reply_to"] == "other.invalid"


def test_matching_reply_to_is_not_flagged():
    p = base()
    p["headers"][hdr("Reply", "To")] = "alice@example.invalid"
    assert "reply_to_mismatch" not in ids(analyze_headers(p))


def test_missing_headers_reported_without_crashing():
    r = analyze_headers({"headers": {}, "received": []})
    assert "missing_header" in ids(r)
    assert "no_received" in ids(r)


def test_received_parsing_and_order():
    p = base()
    p["received"] = [
        "from b.example.invalid by c.example.invalid; Mon, 05 Oct 2026 10:02:00 +0000",
        "from a.example.invalid ([10.0.0.5]) by b.example.invalid; "
        "Mon, 05 Oct 2026 10:01:00 +0000",
    ]
    r = analyze_headers(p)
    assert r["hop_count"] == 2
    assert r["hops"][0]["from_host"] == "a.example.invalid"
    assert r["hops"][0]["ips"] == ["10.0.0.5"]
    assert "received_time_order" not in ids(r)


def test_out_of_order_timestamps_flagged():
    p = base()
    p["received"] = [
        "from a.example.invalid by b.example.invalid; Mon, 05 Oct 2026 10:01:00 +0000",
        "from b.example.invalid by c.example.invalid; Mon, 05 Oct 2026 10:02:00 +0000",
    ]
    assert "received_time_order" in ids(analyze_headers(p))


def test_display_name_spoof():
    p = base()
    p["headers"]["From"] = '"ceo@bank.invalid" <attacker@evil.invalid>'
    assert "display_name_spoof" in ids(analyze_headers(p))


def test_parse_received_without_timestamp():
    assert parse_received("from x by y")["timestamp"] is None

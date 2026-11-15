import sys
from pathlib import Path
from email.message import EmailMessage

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from email_parser import parse_eml, hdr


def make_eml(tmp_path, with_attachment=False):
    msg = EmailMessage()
    msg["From"] = "sender@example.invalid"
    msg["To"] = "victim@example.invalid"
    msg["Subject"] = "Test message"
    msg[hdr("Reply", "To")] = "other@example.invalid"
    msg.set_content("Visit http://example.invalid/login")
    if with_attachment:
        msg.add_attachment(
            b"hello",
            maintype="application",
            subtype="octet" + chr(45) + "stream",
            filename="note.bin",
        )
    path = tmp_path / "t.eml"
    path.write_bytes(bytes(msg))
    return path


def test_basic_headers(tmp_path):
    r = parse_eml(make_eml(tmp_path))
    assert r["headers"]["From"] == "sender@example.invalid"
    assert r["headers"][hdr("Reply", "To")] == "other@example.invalid"
    assert "example.invalid/login" in r["text_body"]
    assert r["message_sha256"]


def test_attachment_metadata(tmp_path):
    r = parse_eml(make_eml(tmp_path, with_attachment=True))
    assert len(r["attachments"]) == 1
    att = r["attachments"][0]
    assert att["filename"] == "note.bin"
    assert att["extension"] == ".bin"
    assert att["size"] == 5
    assert att["sha256"].startswith("2cf24dba")


def test_detected_type_from_magic_bytes(tmp_path):
    msg = EmailMessage()
    msg["From"] = "a@example.invalid"
    msg.set_content("see attached")
    msg.add_attachment(
        b"MZ" + b"\x00" * 10,
        maintype="application",
        subtype="pdf",
        filename="invoice.pdf",
    )
    path = tmp_path / "x.eml"
    path.write_bytes(bytes(msg))
    att = parse_eml(path)["attachments"][0]
    assert att["content_type"] == "application/pdf"
    assert att["detected_type"] == "windows_executable"


def test_malformed_file_does_not_crash(tmp_path):
    bad = tmp_path / "bad.eml"
    bad.write_bytes(b"\x00\x01 not an email")
    r = parse_eml(bad)
    assert isinstance(r, dict)


def test_missing_file_does_not_crash(tmp_path):
    r = parse_eml(tmp_path / "nothing.eml")
    assert r["parse_errors"]

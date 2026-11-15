"""Safe .eml parser (task W1_02, plus attachment metadata for W1_08).

Reads message structure only. It never executes, opens or renders any content.
The return value is a plain dict so the other analyzer modules stay decoupled.
"""
import hashlib
import json
import sys
from email import policy
from email.parser import BytesParser

H = chr(45)


def hdr(*parts):
    """Build a header name such as Reply, To by joining the parts with a hyphen."""
    return H.join(parts)


# Header names the other modules rely on. Missing ones are stored as None.
WANTED_HEADERS = [
    "From", "To", "Cc", "Subject", "Date",
    hdr("Reply", "To"),
    hdr("Return", "Path"),
    hdr("Message", "ID"),
    hdr("Authentication", "Results"),
    hdr("DKIM", "Signature"),
    hdr("Received", "SPF"),
]

# Real file signatures (magic bytes). Used to compare against the claimed type.
SIGNATURES = [
    (b"MZ", "windows_executable"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip_or_ooxml"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2_office"),
    (b"Rar!", "rar"),
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "seven_zip"),
    (b"{\\rtf", "rtf"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
]


def sniff_type(data):
    """Return a short label from the first bytes of a file, or unknown."""
    for magic, label in SIGNATURES:
        if data.startswith(magic):
            return label
    return "unknown"


def _text_of(part):
    """Decode a text part. Falls back to a lossy decode on bad charsets."""
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf8", errors="replace")


def _empty_result(path):
    return {
        "file": str(path),
        "message_sha256": None,
        "headers": {},
        "received": [],
        "content_types": [],
        "text_body": "",
        "html_body": "",
        "attachments": [],
        "defects": [],
        "parse_errors": [],
    }


def parse_eml(path):
    """Parse an .eml file and return a dict. Never raises on odd or broken input."""
    result = _empty_result(path)

    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception as exc:
        result["parse_errors"].append("cannot read file: " + str(exc))
        return result

    result["message_sha256"] = hashlib.sha256(raw).hexdigest()

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        result["parse_errors"].append("cannot parse message: " + str(exc))
        return result

    # Structural problems reported by the email library (useful evidence).
    result["defects"] = [type(d).__name__ for d in msg.defects]

    # Headers: keep the raw text exactly as received, None when absent.
    for name in WANTED_HEADERS:
        try:
            value = msg.get(name)
        except Exception as exc:
            value = None
            result["parse_errors"].append(name + ": " + str(exc))
        result["headers"][name] = str(value) if value is not None else None

    # Received chain, newest hop first, exactly as stored in the message.
    try:
        result["received"] = [str(v) for v in msg.get_all("Received", [])]
    except Exception as exc:
        result["parse_errors"].append("Received: " + str(exc))

    # Walk the MIME tree.
    try:
        for part in msg.walk():
            result["content_types"].append(part.get_content_type())
            if part.is_multipart():
                continue

            filename = part.get_filename()
            disposition = part.get_content_disposition()

            if filename or disposition == "attachment":
                data = part.get_payload(decode=True) or b""
                extension = ""
                if filename and "." in filename:
                    extension = "." + filename.rsplit(".", 1)[1].lower()
                result["attachments"].append({
                    "filename": filename,
                    "extension": extension,
                    "content_type": part.get_content_type(),
                    "disposition": disposition,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "magic": data[:8].hex(),
                    "detected_type": sniff_type(data),
                })
            elif part.get_content_type() == "text/plain":
                result["text_body"] += _text_of(part)
            elif part.get_content_type() == "text/html":
                result["html_body"] += _text_of(part)
    except Exception as exc:
        result["parse_errors"].append("mime walk: " + str(exc))

    return result


def main(argv):
    if len(argv) < 2:
        print("usage: python email_parser.py <file.eml>")
        return 1
    print(json.dumps(parse_eml(argv[1]), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

"""Generates SAFE lab .eml samples (reserved domains only: example.com / .invalid / .test)."""
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

OUT = Path(__file__).parent / "samples"
OUT.mkdir(exist_ok=True)

def save(name, msg):
    (OUT / name).write_bytes(msg.as_bytes())

# 1) Benign
m = EmailMessage()
m["From"] = "Alice HR <alice@example.com>"
m["To"] = "labuser@example.test"
m["Subject"] = "Team meeting tomorrow"
m["Date"] = "Mon, 02 Nov 2026 09:00:00 +0000"
m["Message-ID"] = "<benign-001@example.com>"
m["Return-Path"] = "<alice@example.com>"
m["Received"] = "from mail.example.com (mail.example.com [192.0.2.10]) by mx.example.test with ESMTPS; Mon, 02 Nov 2026 09:00:05 +0000"
m["Authentication-Results"] = "mx.example.test; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
m.set_content("Hi, the meeting is at 10:00 tomorrow. See you.")
save("benign_001.eml", m)

# 2) Phishing-like (spoofed display name, mismatched Reply-To/Return-Path, auth fail, suspicious URL, attachment)
m = EmailMessage()
m["From"] = "Microsoft Support <support@micros0ft-security.invalid>"
m["To"] = "labuser@example.test"
m["Reply-To"] = "collector@evil-reply.invalid"
m["Return-Path"] = "<bounce@random-host.invalid>"
m["Subject"] = "URGENT: Your account will be suspended"
m["Date"] = "Tue, 03 Nov 2026 03:12:00 +0000"
m["Message-ID"] = "<phish-001@random-host.invalid>"
m["Received"] = "from unknown (HELO mail.random-host.invalid) (198.51.100.23) by mx.example.test with SMTP; Tue, 03 Nov 2026 03:12:10 +0000"
m["Received"] = "from relay1.random-host.invalid (relay1.random-host.invalid [203.0.113.45]) by mail.random-host.invalid with ESMTP; Tue, 03 Nov 2026 03:12:05 +0000"
m["Authentication-Results"] = "mx.example.test; spf=fail smtp.mailfrom=random-host.invalid; dkim=none; dmarc=fail header.from=micros0ft-security.invalid"
m.set_content("Your account will be suspended. Verify now: http://login.micros0ft-security.invalid/verify?id=123")
m.add_alternative('<html><body><p>Verify now: <a href="http://login.micros0ft-security.invalid/verify?id=123">https://microsoft.com/secure</a></p></body></html>', subtype="html")
m.add_attachment(b"BENIGN TEST CONTENT - NOT MALWARE", maintype="application", subtype="octet-stream", filename="Invoice_2026.pdf.exe")
save("phish_001.eml", m)

# 3) Incomplete (no auth results, few headers)
m = EmailMessage()
m["From"] = "unknown@example.com"
m["Subject"] = "Hello"
m.set_content("No other headers here.")
save("incomplete_001.eml", m)

# 4) Malformed
(OUT / "malformed_001.eml").write_bytes(b"This is not really an email\n\x00\xff\xfe garbage\n")
print("Samples created in", OUT)

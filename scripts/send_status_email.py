#!/usr/bin/env python3
"""Send a Kali status-change email using SMTP environment variables."""

from __future__ import annotations

import os
import smtplib
import ssl
import sys
from email.message import EmailMessage


def main() -> int:
    required = ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "NOTIFY_EMAIL")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        print(f"Email skipped; missing secrets: {', '.join(missing)}")
        return 0

    message = EmailMessage()
    message["Subject"] = os.environ["EMAIL_SUBJECT"]
    message["From"] = os.environ.get("SMTP_FROM") or os.environ["SMTP_USER"]
    message["To"] = os.environ["NOTIFY_EMAIL"]
    message.set_content(os.environ["EMAIL_BODY"])

    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT") or "465")
    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as smtp:
            smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.starttls(context=context)
            smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            smtp.send_message(message)
    print(f"Status-change email sent to {message['To']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

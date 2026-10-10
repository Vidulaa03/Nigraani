"""Expose only the signed Twilio status callback through a local tunnel.

Run from the repository root with:
    python -m backend.twilio_callback_proxy
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

from backend.twilio_service import RequestValidator, handle_twilio_callback


CALLBACK_PATH = "/api/dashboard/calls/callback"
MAX_BODY_BYTES = 16_384


class CallbackHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != CALLBACK_PATH:
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length < 1 or content_length > MAX_BODY_BYTES:
            self.send_error(413)
            return

        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            self.send_error(415)
            return

        auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
        signature = self.headers.get("X-Twilio-Signature")
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
        host = host.split(",", 1)[0].strip()
        if not auth_token or not signature or not host or RequestValidator is None:
            self.send_error(403)
            return

        body = self.rfile.read(content_length).decode("utf-8", errors="strict")
        form_data = {key: values[-1] for key, values in parse_qs(body, keep_blank_values=True).items()}
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "https").split(",", 1)[0].strip()
        callback_url = f"{forwarded_proto}://{host}{self.path}"
        validator = RequestValidator(auth_token)
        if not validator.validate(callback_url, form_data, signature):
            self.send_error(403)
            return

        result = handle_twilio_callback(form_data)
        payload = json.dumps(result).encode("utf-8")
        self.send_response(200 if result.get("success") else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        # Do not log callback form fields or phone numbers.
        print(f"Twilio callback proxy: {format % args}")


if __name__ == "__main__":
    port = int(os.environ.get("TWILIO_CALLBACK_PROXY_PORT", "8765"))
    server = ThreadingHTTPServer(("127.0.0.1", port), CallbackHandler)
    print(f"Signed Twilio callback listener on 127.0.0.1:{port}{CALLBACK_PATH}")
    server.serve_forever()

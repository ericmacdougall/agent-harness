#!/usr/bin/env python3
"""Disposable click-test helper: plain-HTTP 127.0.0.1:8792 -> the local wrangler preview on https 8791, adding the
preview's synthetic Basic credential from .pw so a browser that cannot answer a Basic dialog can open the staged build.
Binds to loopback only; the credential is read from the file and never printed. Stop it with ah.py kill."""
import base64, http.client, http.server, ssl, sys, threading
from pathlib import Path

UPSTREAM = ("127.0.0.1", 8791)
AUTH = "Basic " + base64.b64encode(b"eric:" + Path(".pw").read_text().strip().encode()).decode()
CTX = ssl._create_unverified_context()
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate", "host", "authorization"}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_any(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        headers["Authorization"] = AUTH
        conn = http.client.HTTPSConnection(*UPSTREAM, context=CTX, timeout=60)
        conn.request(self.command, self.path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read()
        self.send_response(response.status)
        for key, value in response.getheaders():
            if key.lower() not in HOP and key.lower() != "content-length":
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = handle_any

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8792), Handler)
    print("preview proxy on http://127.0.0.1:8792", flush=True)
    server.serve_forever()

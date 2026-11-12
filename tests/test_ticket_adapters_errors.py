"""GoodQA adapter: a plain-text MCP error is reported as an error, not as "unexpected shape" (goodqa#15754 hardening G0).

Evidence (2026-11-12, live goodqa.app): `list_issues` without projectId and `search_issues` with `query` instead of
`search` return isError with the text "MCP error -32602: Input validation error: ... at projectId" (not JSON). The
adapter parsed content[0].text as JSON before looking at isError, so both calls raised "GoodQA returned an unexpected
shape", and the launch review concluded the list tools were broken. With projectId and `search` both return
{counts, issues, listCompleteness, nextCursor}. On ee9fc12d the first two tests below fail.
"""
import http.server
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ticket_adapters as ta  # noqa: E402


class Server:
    def __init__(self, text, is_error):
        outer = self
        self.text, self.is_error = text, is_error

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["content-length"]))
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                    "content": [{"type": "text", "text": outer.text}], "isError": outer.is_error}})
                payload = ("event: message\ndata: " + body + "\n\n").encode()
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d/v1/mcp" % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class PlainTextErrors(unittest.TestCase):
    def adapter(self, text, is_error):
        server = Server(text, is_error)
        self.addCleanup(server.close)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        key = Path(tmp.name, "member.key")
        key.write_text("test-key\n")
        key.chmod(0o600)
        return ta.GoodQAAdapter({"endpoint": server.url, "key_file": str(key), "org_id": "org-1", "attempts": 1})

    def test_validation_error_names_the_field(self):
        ad = self.adapter("MCP error -32602: Input validation error: Invalid arguments for tool list_issues: Invalid "
                          "input: expected string, received undefined at projectId", True)
        with self.assertRaises(ta.TicketSystemUnavailable) as caught:
            ad.call("list_issues", {"orgId": "org-1"})
        self.assertIn("MCP error -32602 (invalid arguments at projectId) for list_issues", str(caught.exception))
        self.assertNotIn("unexpected shape", str(caught.exception))

    def test_other_plain_text_error_keeps_only_the_code(self):
        ad = self.adapter("MCP error -32603: internal failure while reading secret-token-abc123 from /Users/x", True)
        with self.assertRaises(ta.TicketSystemUnavailable) as caught:
            ad.call("list_issues", {"projectId": "p"})
        self.assertIn("MCP error -32603 for list_issues", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("/Users", str(caught.exception))

    def test_plain_text_error_keeps_ah_ticket_on_the_unavailable_path(self):
        # Review L1 (a75885cf): a returned {"__error__"} dict made list_projects report "project not visible".
        import ah_ticket
        ad = self.adapter("MCP error -32603: internal failure", True)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        body = Path(tmp.name, "b.md")
        body.write_text("body")
        with self.assertRaises(ah_ticket.TicketCreateError) as caught:
            ah_ticket.create("goodqa", "probe title", str(body), home=Path(tmp.name), adapter=ad, mod=ta,
                             redactor=lambda s: s)
        self.assertEqual(caught.exception.code, "ticket_unavailable")
        self.assertNotIn("not visible", str(caught.exception))

    def test_non_json_success_is_still_an_unexpected_shape(self):
        ad = self.adapter("not json", False)
        with self.assertRaises(ta.TicketSystemUnavailable) as caught:
            ad.call("list_issues", {"projectId": "p"})
        self.assertIn("unexpected shape", str(caught.exception))

    def test_json_error_payload_unchanged(self):
        ad = self.adapter(json.dumps({"data": {"error": {"code": "not_found"}}}), True)
        self.assertEqual(ad.call("get_issue_by_number", {}), {"__error__": "not_found"})


if __name__ == "__main__":
    unittest.main()

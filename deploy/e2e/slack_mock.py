# Loopback stand-in for a Slack incoming webhook: appends each payload to a file.
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open("/var/log/slack-mock.jsonl", "ab") as f: f.write(body + b"\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 9999), H).serve_forever()

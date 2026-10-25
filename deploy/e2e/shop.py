# The "business app" this test server exists to run.
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"ok": True} if self.path == "/health" else {"shop": "welcome"}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a):
        with open("/var/log/shop-access.log", "a") as f: f.write(self.address_string() + " " + (a[0] % a[1:]) + "\n")
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()

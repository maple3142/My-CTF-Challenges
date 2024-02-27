from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import re, os


if os.path.exists("/flag"):
    with open("/flag") as f:
        FLAG = f.read().strip()
else:
    FLAG = os.environ.get("FLAG", "flag{this_is_a_fake_flag}")
URL_REGEX = re.compile(r"https?://[a-zA-Z0-9.]+(/[a-zA-Z0-9./?#]*)?")


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/flag":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(FLAG.encode())
            return
        query = parse_qs(urlparse(self.path).query)
        redir = None
        if "redir" in query:
            redir = query["redir"][0]
            if not URL_REGEX.match(redir):
                redir = None
        self.send_response(302 if redir else 200)
        if redir:
            self.send_header("Location", redir)
        self.end_headers()
        self.wfile.write(b"Hello world!")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("", 7777), RequestHandler)
    server.allow_reuse_address = True
    print("Starting server, use <Ctrl-C> to stop")
    server.serve_forever()

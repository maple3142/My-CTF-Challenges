from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import os
import mimetypes
from urllib.parse import parse_qs
from threading import Thread
from subprocess import Popen, PIPE


def report(url):
    public_host = os.environ.get("PUBLIC_HOST", "http://nginx/")
    p = Popen(["python3", "bot.py", public_host, url], stdout=PIPE, stderr=PIPE)
    p.wait()
    return


class RequestHandler(BaseHTTPRequestHandler):
    def respond(self, headers=None):
        if headers is None:
            headers = {}
        if "Content-Security-Policy" not in headers:
            headers["Content-Security-Policy"] = "default-src 'self'"
        if "Content-Type" not in headers:
            headers["Content-Type"] = "text/html"
        self.send_response(200)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        if self.path == "/":
            self.path = "/index.html"
        filepath = self.path[1:]
        if ".." not in filepath and "/" not in filepath:
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    typ, _ = mimetypes.guess_type(filepath)
                    self.respond({"Content-Type": typ})
                    self.wfile.write(f.read())
                    return
        self.respond()
        self.wfile.write(f"404 {self.path} Not Found".encode())

    def do_POST(self):
        if self.path.startswith("/report"):
            url = parse_qs(self.path.split("?")[1])["url"][0]
            t = Thread(target=report, args=(url,))
            t.start()
            self.respond()
            self.wfile.write(b"Reported")
            return
        self.respond()
        self.wfile.write(f"404 {self.path} Not Found".encode())


if __name__ == "__main__":
    server = ThreadingHTTPServer(("", 8000), RequestHandler)
    print("Starting server, use <Ctrl-C> to stop")
    server.serve_forever()

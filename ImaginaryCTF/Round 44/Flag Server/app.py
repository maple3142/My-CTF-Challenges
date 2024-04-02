import bottle, os, traceback
from bottle import request, response
from playwright.sync_api import sync_playwright
from urllib.parse import quote_plus
import string

flag = os.environ.get(
    "FLAG", "jctf{red_flags_and_fake_flags_form_an_equivalence_class}"
)
public_host = os.environ.get("PUBLIC_HOST", "http://localhost:3000/")
visit_flag_url = public_host + "flag?flag=" + quote_plus(flag)
print(f"{visit_flag_url = }")


def sanitize(s):
    bad = "<>\"'{}\0\n\r"
    return "".join(c for c in s if c not in bad)


def secure(callback):
    def wrapper(*args, **kwargs):
        response.headers["Content-Security-Policy"] = "default-src 'none';"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        return callback(*args, **kwargs)

    return wrapper


bottle.install(secure)


@bottle.post("/visit")
def visit():
    url = sanitize(request.forms.get("url"))
    if not url.startswith("http://") and not url.startswith("https://"):
        return "Invalid URL"
    print(f"Visiting {url}")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--js-flags=--jitless,--no-expose-wasm",
                "--disable-gpu",
                "--disable-dev-shm-usage",
            ],
        )
        context = browser.new_context()
        try:
            page = context.new_page()
            page.goto(
                visit_flag_url, wait_until="networkidle", timeout=5000
            )  # this is essentially localhost, so it should be fast
            page.close()
        except:
            traceback.print_exc()
            return "Failed to visit the flag URL, please report this to the admin"

        try:
            page = context.new_page()
            page.goto(url, wait_until="networkidle")
            page.close()
        except:
            traceback.print_exc()
            return "Failed to visit the requested URL"
    return "Visited!"


@bottle.get("/visit")
def index():
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Admin Bot</title>
</head>
<body>
    <pre>{public_host = }</pre>
    <form action="/visit" method="post">
        <label for="url">URL:</label>
        <input type="url" name="url" required>
        <input type="submit">
    </form>
</body>
</html>
"""


@bottle.get("/source")
def source():
    with open(__file__) as f:
        response.content_type = "text/plain"
        return f.read()


@bottle.get("/Dockerfile")
def dockerfile():
    with open("Dockerfile") as f:
        response.content_type = "text/plain"
        return f.read()


@bottle.get("/")
def index():
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Flag Server</title>
</head>
<body>
    <h1>Flag Server</h1>
    <form action="/flag">
        <label for="flag">Flag:</label>
        <input type="text" name="flag" required>
        <input type="submit">
    </form>
    <a href="/source">Source</a>
</body>
</html>
"""


@bottle.get("/<_:re:.+>")
def flag(_):
    flag = request.get_cookie("flag", "No flag found...")
    if request.query.flag:
        flag = sanitize(request.query.flag)
        response.set_cookie("flag", flag, httponly=True)
    return flag


application = bottle.default_app()

if __name__ == "__main__":
    bottle.run(host="localhost", port=3000)

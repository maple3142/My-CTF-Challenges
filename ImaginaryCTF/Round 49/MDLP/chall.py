from Crypto.Util.number import sieve_base
import re, math

with open("flag.txt", "rb") as f:
    flag = f.read().strip()
assert re.fullmatch(r"ictf\{[a-zA-Z0-9_]{23}\}", flag.decode())
secret = flag[5:-1]

p = 60136177367560631039092956703653203338217286978701852857028839528525260293087
y = math.prod(pow(g, x, p) for g, x in zip(sieve_base, secret)) % p
print(f"{y = }")
# y = 36460313315646730969501498120968068746377445179920045296321232935228480996523

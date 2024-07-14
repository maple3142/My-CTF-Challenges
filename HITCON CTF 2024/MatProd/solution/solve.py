from sage.all import load
import sys
from hashlib import sha256
from Crypto.Cipher import AES

msg1 = int(sys.argv[1])
msg2 = int(sys.argv[2])
output_file = sys.argv[3] if len(sys.argv) > 3 else "output.sobj"

data = load(output_file)

H = sha256()
H.update(str(msg1).encode())
H.update(str(msg2).encode())
key = H.digest()
cipher = AES.new(key, AES.MODE_CTR, nonce=data["nonce"])
enc_flag = data["enc_flag"]
flag = cipher.decrypt(enc_flag)
print(flag)

# python solve_direct.py # outputs 5176722979020181474904133171562570897924
# python solve_alternating.py # outputs 337191443897730593259908466860345320901
# python solve.py 5176722979020181474904133171562570897924 337191443897730593259908466860345320901
# hitcon{it_is_still_leaking_some_traces_in_some_way}

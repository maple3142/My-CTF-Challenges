from pwn import process, remote
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha1
import ast

p = 0xAFCAFD4482568D44AF985A4E4575AE8EAF3C843E69C1D4E4AFAE1B4BCDABE0034D7010C845A88BE94BDA402B9ACE25ADD7378A6AFAFE0E9798C9C0C93C6C81439E872DC77078CBD2BA0E140C29AEBCE89854D43700D4946B6C8E4BA5E6058FA2794207AD1F2CA9CCE64DE971F99EFDAA6AFD34B0B98F0132A8689DB5B371E6602C3A81D17D1BAE4FD350217A8C531555DF1FB06A9BDB536AE8F2A23EF04FC9D1825A3280F3ADAD4A2B34C4C04040AC748E72D953EB15EA743A5C4D941641874AD79DABD35A47394124BF1944BD84E64D094AC1442C49A293EF7B52DB3A7C1D67F1DE80AA4DF4E0221B43194C0721F9183199CD0991BDBA45FAE080B68EAE184B
q = (p - 1) // 2
g = 2

with open("shattered-1.pdf", "rb") as f:
    m1 = f.read()[:320]

with open("shattered-2.pdf", "rb") as f:
    m2 = f.read()[:320]

io = process(["python", "../server.py"], env={"FLAG": "FLAG{test_flag}"})
# io = remote("localhost", 6002)
io.recvuntil(b"y = ")
y = int(io.recvlineS())
io.recvuntil(b"flag_ct.hex() = ")
flag_ct = bytes.fromhex(ast.literal_eval(io.recvlineS()))


def sign(m: bytes):
    io.recvuntil(b"m = ")
    io.sendline(m.hex().encode())
    io.recvuntil(b"sign(m, x) = ")
    return ast.literal_eval(io.recvlineS())


r1, s1 = sign(m1)
r2, s2 = sign(m2)
assert r1 == r2


def H(m: bytes):
    return sha1(m).digest()


def HH(m: bytes):
    return bytes_to_long(H(H(m) + m))


k = ((HH(m1) - HH(m2)) * pow(s1 - s2, -1, q)) % q
x = ((s1 * k - HH(m1)) * pow(r1, -1, q)) % q
if pow(g, x, p) != y:
    x += q
assert pow(g, x, p) == y

key = sha1(str(x).encode()).digest()[:16]
flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(flag_ct), 16)
print(flag)

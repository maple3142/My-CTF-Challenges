from sage.all import *
from pwn import process
from server import p, k, F, to_element, to_list
from lll_cvp import reduce_mod_p
from Crypto.Cipher import AES
import os, ast


def decrypt(key, ct):
    nonce = ct[:8]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct[8:])


io = process(["python", "server.py"])


def get_pair():
    pt = os.urandom(8).hex().encode()
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"input: ", pt)
    io.recvuntil(b"mac(input): ")
    mac = ast.literal_eval(io.recvline().strip().decode())
    return to_element(pt), to_element(mac)


# crediting @soon_haari for the idea of this solution

# ffmac(key, x) = c1 * x^(p+1) + c2
# let's solve for c1, c2
x1, y1 = get_pair()
x2, y2 = get_pair()
c1, c2 = matrix([[x1 ** (p + 1), 1], [x2 ** (p + 1), 1]]).solve_right(vector([y1, y2]))

# do a sanity check
x3, y3 = get_pair()
assert c1 * x3 ** (p + 1) + c2 == y3, "wtf"

io.sendlineafter(b"> ", b"2")
io.recvuntil(b"challenge: ")
challenge = bytes.fromhex(io.recvline().strip().decode())
tgt = to_list(c1 * to_element(challenge) ** (p + 1) + c2)
io.sendlineafter(b"mac: ", ",".join(map(str, tgt)).encode())

io.recvuntil(b"ciphertext: ")
ciphertext = bytes.fromhex(io.recvline().strip().decode())
io.recvuntil(b"mac(key): ")
mackey = to_element(ast.literal_eval(io.recvline().strip().decode()))

# there are many roots to x^(2^127)=c=(mackey-c2)/c1
# find an arbitrary solution a that a^(2^127)=c
# and an unity root b that b^(2^127)=1 (b is an element with order 2^127)
# then the target short key solution would be in the form of a*b^i

# apparently 2^127=p+1, and (p+1) divides p^2-1 so we expect b would be an element like GF(p^2)
# this means b^i would be in the form of aa*r+bb for some r such that r^2+1=0 (aa, bb are arbitrary)
# so key=a*b^i=(a*r)*aa+(a)*bb and this can be found with LLL

# the method above is @soon_haari's solution
# based on it, I observed that b^i=aa*r+bb means b^i would be in a linear subspace with low rank (2) of GF(p)^k
# similarly, the space of key=a*b^i is also small
# so we can easily construct basis matrix to the subspace and use LLL to find a short vector to it, which is the key!

a = ((mackey - c2) / c1).nth_root(2**127)
b = F(1).nth_root(2**127)
solution_space = matrix([to_list(a * b**i) for i in range(1, 42)])
assert solution_space.rank() == 2
key = reduce_mod_p(solution_space[:2], p)[0]
if key[0] < 0:
    key = -key
print(key)
print(decrypt(bytes(key), ciphertext))

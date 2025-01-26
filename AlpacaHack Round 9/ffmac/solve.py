from sage.all import *
from pwn import process
from server import p, k, F, to_element, to_list
from lll_cvp import reduce_mod_p, polynomials_to_matrix
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


quadk = binomial(k + 1, 2) + k + 1


def to_quad(v):
    ret = [1]
    ret.extend(list(v))
    for i in range(k):
        for j in range(i, k):
            ret.append(v[i] * v[j])
    assert len(ret) == quadk
    return vector(ret)


rows = []
rhs = []
for _ in range(quadk + 10):
    x, z = get_pair()
    rows.append(to_quad(to_list(x)))
    rhs.append(to_list(z))
mat = matrix(GF(p), rows).solve_right(matrix(GF(p), rhs)).T

io.sendlineafter(b"> ", b"2")
io.recvuntil(b"challenge: ")
challenge = bytes.fromhex(io.recvline().strip().decode())
tgt = mat * vector(GF(p), to_quad(challenge))
io.sendlineafter(b"mac: ", ",".join(map(str, tgt)).encode())

io.recvuntil(b"ciphertext: ")
ciphertext = bytes.fromhex(io.recvline().strip().decode())
io.recvuntil(b"mac(key): ")
mackey = to_element(ast.literal_eval(io.recvline().strip().decode()))
tgtv = vector(GF(p), to_list(mackey))

key_sym = PolynomialRing(GF(p), k, "x").gens()
eqs = list(mat * to_quad(key_sym) - tgtv)
I = ideal(eqs)
print("compute gb")
gb = I.groebner_basis()
print("done")
for x in gb:
    print(x)
M, monos = polynomials_to_matrix([f for f in gb if f.degree() == 1])
print(monos)
mrk = reduce_mod_p(M.right_kernel_matrix(), p)
key = [int(x) for x in mrk[0] * sign(mrk[0][0])]
print(key)
print(decrypt(bytes(key), ciphertext))

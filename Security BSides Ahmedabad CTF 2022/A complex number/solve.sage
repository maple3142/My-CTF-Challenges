from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open("output.txt") as f:
    bits = 100
    C = ComplexField(bits)
    r = C(f.readline().strip())
    print(r)
    real = [(r ^ i)[0] for i in range(16)]
    imag = [(r ^ i)[1] for i in range(16)]

    K = 2 ** (bits - 1)
    M = matrix([[round(K * x) for x in real], [round(K * x) for x in imag]]).T.augment(
        matrix.identity(16)
    )
    key = bytes([abs(x) for x in M.LLL()[0][2:]])
    ct = bytes.fromhex(f.readline().strip())
    cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
    print(unpad(cipher.decrypt(ct), 16).decode())

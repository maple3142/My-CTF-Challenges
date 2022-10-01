flag = open("flag.txt", "rb").read().strip()

def H(flag):
    return bytes([pow(x ^ hash(tuple(flag[:i])), 0x133713371337, 251) & 0xFF for i, x in enumerate(flag)])

enc = H(flag)
print(enc.hex())

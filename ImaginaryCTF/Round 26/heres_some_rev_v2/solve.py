def H(flag):
    return bytes([pow(x ^ hash(tuple(flag[:i])), 0x133713371337, 251) & 0xFF for i, x in enumerate(flag)])

enc = bytes.fromhex('a9af6782b63c6cc8dcd29411e1463d3c46d6df794e7372187a47cf8b1d42167a85187f9eeb6567afda5d42d9c724c2cee7a5e2e6392f2b5c3e066f46990fc9063fa73ba8aad49bd7a0')
rec = b""
while not rec.endswith(b"}"):
    for i in range(256):
        enc2 = H(rec + bytes([i]))
        if enc[len(rec)] == enc2[len(rec)]:
            rec += bytes([i])
            print(rec)
            break

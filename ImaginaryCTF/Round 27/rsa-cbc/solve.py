exec(open("output.txt").read())

e = 65537

LEN = 2048 // 8
blks = [iv] + [ct[i : i + LEN] for i in range(0, len(ct), LEN)]
blks = [int.from_bytes(x, "big") for x in blks]

flag = ''
for prv, cur in zip(blks, blks[1:]):
    for i in range(256):
        if pow(prv + i, e, n) == cur:
            flag += chr(i)
            break
    print(flag)

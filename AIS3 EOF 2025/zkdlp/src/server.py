from Crypto.Util.number import bytes_to_long
from hashlib import shake_128
import os, random

p = 0x2CDE2997126F706BD27498A9FA07E93F321B4932982BC455910FF694160DB5484257D0886EC66E5D7BE59ECFD16AAFF6B5BD57E600FAB97E7CF75D76A7F12BC4619A036ED8787F4508CC7C1FB35689575E007B7DC6B1EECC4B9BC2E91AA31FBE027C62BFF3E2065912591ECC1C361CEEAE75B382F1BD7D967633FD91476A3ABC4AD22CD3372C3FC40C2841B3BC70DAC11E3A6631AB3BE49AB9F748AE9093FBAB15B5457244363F444D146C0ADE84CC1AB0D0CFB2AD329483E957235EDD0085BD2F5CDAFCD77D00622A9DFCD3C0098DCB42C7EF1DEE808E8216F0F0638F51D26614B0C61352A13565098FE60146FF7E46FAEBCB75629DAF517880E36AEEE617B9F
q = (p - 1) // 2
g = 2
assert pow(g, q, p) == 1


def main():
    flag = os.environ.get("FLAG", "flag{fake_flag}")
    hflag = shake_128(flag.encode()).digest(q.bit_length() // 8)
    x = bytes_to_long(hflag)
    y = pow(g, x, p)

    print("Do you know the flag?")
    print(f"{y = }")

    wins = 0
    while wins < 10:
        t = int(input("t = ")) % p
        if t == 0:
            print("Nope")
            return
        c = random.randrange(q)
        print(f"{c = }")
        s = int(input("s = ")) % q
        if pow(g, s, p) == t * pow(y, c, p) % p:
            print("Hmm, you probably know the flag!")
            wins += 1
        else:
            print("No, you don't know the flag :(")
            wins = 0

    print("Okay, I am finally convinced that you know the flag:")
    print(flag)


if __name__ == "__main__":
    main()

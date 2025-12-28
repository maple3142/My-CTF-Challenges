from Crypto.Util.number import bytes_to_long, getPrime, getRandomRange


def gen(sz):
    p = getPrime(sz)
    q = getPrime(sz)
    n = p * q
    return n


def poly(f, x):
    r = 0
    for c in f:
        r = r * x + c
    return r


def main():
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
        m = bytes_to_long(flag)

    n = gen(655)
    f = [getRandomRange(0, 65537) for _ in range(37)]
    cs = [pow(m, poly(f, i), n) for i in range(65537, 65537 + 87)]
    print(f"{cs = }")


if __name__ == "__main__":
    main()

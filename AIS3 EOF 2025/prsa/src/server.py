from Crypto.Util.number import getPrime, getRandomRange, bytes_to_long
import os


def keygen(sz):
    p = getPrime(sz // 2)
    q = getPrime(sz // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 0x10001
    d = pow(e, -1, phi)
    g = 1 + n
    mu = pow(phi, -1, n)
    pk = (n, e, g)
    sk = (n, d, phi, mu)
    return pk, sk


def rsa_encrypt(pk, m):
    n, e, g = pk
    return pow(m, e, n)


def rsa_decrypt(sk, c):
    n, d, phi, mu = sk
    return pow(c, d, n)


def paillier_encrypt(pk, m):
    n, e, g = pk
    r = getRandomRange(1, n)
    n2 = n * n
    return (pow(g, m, n2) * pow(r, n, n2)) % n2


def paillier_decrypt(sk, c):
    n, d, phi, mu = sk
    cl = pow(c, phi, n * n)
    return ((cl - 1) // n) * mu % n


def rsa_to_paillier(pk, sk, c):
    return paillier_encrypt(pk, rsa_decrypt(sk, c))


def paillier_to_rsa(pk, sk, c):
    return rsa_encrypt(pk, paillier_decrypt(sk, c))


def pad(m, ln):
    pad_ln = ln - len(m)
    pre = pad_ln // 2
    post = pad_ln - pre
    return os.urandom(pre) + m + os.urandom(post)


def main():
    pk, sk = keygen(1024)

    flag = os.environ.get("FLAG", "flag{fake_flag}")
    m = bytes_to_long(pad(flag.encode(), 1024 // 8 - 1))
    c = rsa_encrypt(pk, m)

    print("RSA Encrypted Flag:")
    print(f"{c = }")

    for _ in range(48763):
        print("1. RSA to Paillier")
        print("2. Paillier to RSA")
        print("3. Exit")
        choice = int(input("> "))
        if choice == 1:
            c = int(input("c = "))
            c = rsa_to_paillier(pk, sk, c)
            print(f"{c = }")
        elif choice == 2:
            c = int(input("c = "))
            c = paillier_to_rsa(pk, sk, c)
            print(f"{c = }")
        elif choice == 3:
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

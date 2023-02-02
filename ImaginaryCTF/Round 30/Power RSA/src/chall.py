from Crypto.Util.number import isPrime, getRandomNBitInteger, bytes_to_long


def getSpecialPrime(n, k):
    while True:
        x = getRandomNBitInteger(n)
        p = x**k + 1
        if isPrime(p):
            return p


p = getSpecialPrime(1024, 2)
q = getSpecialPrime(1024, 2)
n = p * q
e = 65537
flag = open("flag.txt", "rb").read()
m = bytes_to_long(flag)
c = pow(m, e, n)
print(f"{n = }")
print(f"{e = }")
print(f"{c = }")

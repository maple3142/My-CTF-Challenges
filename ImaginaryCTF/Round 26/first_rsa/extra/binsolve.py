# @w0152
# no need to bruteforce the sign of each one
# but brutforcing it is more correct
from Crypto.Util.number import long_to_bytes as ltb


def powmod(a, b, c):
    if b == 0:
        return 1
    h = powmod(a, b // 2, c)
    t = h ^ 2
    if b & 1:
        t *= a
    return t % c


def fff(o):
    low = 0
    high = pow(2, 1024)
    while True:
        mid = (low + high) // 2
        test = powmod(mid, e, n)
        if test == o:
            return mid
        elif test > o:
            high = mid
        else:
            low = mid


with open("output.txt", "r") as f:
    exec(f.read())
print("ictf{" + ltb(fff(c)).decode() + "}")

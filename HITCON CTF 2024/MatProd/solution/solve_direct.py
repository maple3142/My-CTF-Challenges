from sage.all import *
import sys
from chall import direct

output_file = sys.argv[1] if len(sys.argv) > 1 else "output.sobj"

pub, M = load(output_file)["challenges"][0]


def decomposetrace(M, pub, L):
    if len(L) == len(pub):
        return
    if len(pub) - 1 == len(L):
        idx = next(iter(set(range(len(pub))) - set(L)))
        if pub[idx] == M:
            yield L + [idx]
        return
    for i, A in enumerate(pub):
        if i in L:
            continue
        try:
            Mp = A.solve_right(M)
        except ValueError:
            continue
        if int(Mp.trace()) <= int(M.trace()):
            for x in decomposetrace(Mp, pub, L + [i]):
                yield x


sol = next(decomposetrace(M, pub, []))
msg = direct.decode(sol)
assert direct.encrypt(pub, msg) == M
print(msg)

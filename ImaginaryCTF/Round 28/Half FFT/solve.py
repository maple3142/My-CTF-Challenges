import numpy as np
from sage.all import matrix, vector

ar = np.load("output.npy", allow_pickle=False)
N = int(ar[0].real)
freq = ar[1:]


xs = [np.e ** (-1j * 2 * np.pi * k / N) for k in range(N)][N//2:]
print(len(freq), len(xs))

K = 2**32
lhs = []
rhs = []
for x, f in zip(xs, freq):
    real = [int((x**i).real * K) for i in range(N)]
    imag = [int((x**i).imag * K) for i in range(N)]
    lhs.append(real)
    lhs.append(imag)
    rhs.append(int(f.real * K))
    rhs.append(int(f.imag * K))

M = matrix(lhs).T.stack(vector(rhs)).augment(matrix.identity(N + 1))
for row in M.LLL():
    if row[-1] == 1:
        row = -row
    if row[-1] == -1:
        print(row)
        sol = row[len(lhs) : -1]
        offset = ord("i") - sol[0]
        print(bytes((np.array(sol) + offset).tolist()))

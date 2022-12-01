import numpy as np

ar = np.load("output.npy", allow_pickle=False)
N = int(ar[0].real)
freq = ar[1:]


xs = [np.e ** (-1j * 2 * np.pi * k / N) for k in range(N)][N // 2 :]
print(len(freq), len(xs))

lhs = []
rhs = []
for x, f in zip(xs, freq):
    real = [(x**i).real for i in range(N)]
    imag = [(x**i).imag for i in range(N)]
    lhs.append(real)
    lhs.append(imag)
    rhs.append(f.real)
    rhs.append(f.imag)
print(len(lhs), len(lhs[0]))
sol = np.linalg.solve(lhs, rhs)
print(sol)
sol = [int(x) for x in sol]
offset = ord("i") - sol[0]
print(bytes([x + offset for x in sol]))

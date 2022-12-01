import numpy as np

ar = np.load("output.npy", allow_pickle=False)
N = int(ar[0].real)
freq = ar[1:]

print(N)
print(freq.shape)

# for real signal, FFT is symmetric
# and the first value is the sum
seq = np.append(np.append([0], freq[::-1][:-1].conj()), freq)
sol = np.fft.ifft(seq)
sol = [round(x.real) for x in sol]
print(sol)
offset = ord("i") - sol[0]
print(bytes([x + offset for x in sol]))

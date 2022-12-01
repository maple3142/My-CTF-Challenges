import numpy as np

flag = open("flag.txt", "rb").read().strip()
N = len(flag)
freq = np.fft.fft(list(flag))[-N // 2:]
np.save("output.npy", np.insert(freq, 0, N), allow_pickle=False)

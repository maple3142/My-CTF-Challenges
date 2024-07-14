from lll_cvp import polynomials_to_matrix
import random, os
from tqdm import tqdm, trange
import subprocess, time, itertools

PR = PolynomialRing(Zmod(2), 1, "x")
x = PR.gen()
PR1 = PolynomialRing(Zmod(2), "x")


def mask_to_poly(mask, bs=128):
    return PR(PR1(list(map(int, f"{mask:0{bs}b}"[::-1]))) + x**bs)


def lwmp_parity_check(f, n=1024):
    # lwmp can be reduced to find a low weight codework in a linear code
    # this returns the parity check matrix of that code
    k = n - f.degree()
    assert k >= n // 2, "dumer isd only works for k >= n/2"

    xpower = []
    t = 1
    for i in range(n):
        xpower.append(t)
        t = t * x
        if t.degree() >= f.degree():
            t -= f
    M, monos = polynomials_to_matrix(xpower)
    H = matrix(GF(2), M.T[::-1])  # already echelonized
    assert H[:, : H.nrows()] == 1
    assert H.dimensions() == (n - k, n)
    return H, n, k


def solve_lwpm_dumer(f, n=1024):
    # git clone https://github.com/vvasseur/isd
    # cd isd
    # mkdir build
    # cd build
    # cmake .. -DDUMER_LW=1
    # make -j
    # https://decodingchallenge.org/low-weight

    H, n, k = lwmp_parity_check(f, n)
    xb = []
    t = 1
    for i in range(n):
        xb.append(t)
        t = t * x
    xb = vector(xb)

    def write_challenge(He, filename):
        with open(filename, "w") as wf:
            wf.write("# n\n")
            wf.write(f"{n}\n")
            wf.write("# k\n")
            wf.write(f"{k}\n")  # patch parse_input_lw to accept k != n // 2
            wf.write("# seed\n")
            wf.write("0\n")
            wf.write(
                "# H^transpose (each line corresponds to column of H, the identity part is omitted)\n"
            )
            for col in He.T.rows()[He.nrows() :]:
                wf.write("".join(str(x) for x in col) + "\n")

    write_challenge(H, "lw_challenge")
    proc = subprocess.Popen(
        "./isd 8 LW lw_challenge", shell=True, stdout=subprocess.PIPE
    )
    time.sleep(2)
    proc.kill()
    stdout = proc.stdout.read().decode()
    s = stdout.splitlines()[-1].split(": ")[1]
    print("ISD out", s)
    g = vector(map(ZZ, s)) * xb
    assert g % f == 0
    g = g // list(g)[-1][1]
    assert g % f == 0
    return g


f1 = mask_to_poly(0x6D6AC812F52A212D5A0B9F3117801FD5)
f2 = mask_to_poly(0xD736F40E0DED96B603F62CBE394FEF3D)
f3 = mask_to_poly(0xA55746EF3955B07595ABC13B9EBEED6B)
f4 = mask_to_poly(0xD670201BAC7515352A273372B2A95B23)
solve_lwpm_dumer(f1)
solve_lwpm_dumer(f2)
solve_lwpm_dumer(f3)
solve_lwpm_dumer(f4)


def solve_lwpm_birthday(f, w, mx=700):
    if hasattr(f, "univariate_polynomial"):
        f = f.univariate_polynomial()
    x = f.parent().gen()
    assert w >= 2
    w1 = w // 2
    w2 = w - w1
    xpower = []
    t = 1
    for i in range(mx):
        xpower.append(t)
        t = t * x
        if t.degree() >= f.degree():
            t -= f
    tot1 = int(binomial(mx, w1))
    tot2 = int(binomial(mx, w2))
    tbl = {}
    for sel in tqdm(itertools.combinations(range(mx), w1), total=tot1):
        ft = sum(xpower[i] for i in sel)
        tbl[ft] = sel
    for sel in tqdm(itertools.combinations(range(mx), w2), total=tot2):
        ft = sum(xpower[i] for i in sel)
        if ft in tbl and tbl[ft] != sel:
            ftt = sum(x**i for i in tbl[ft] + sel)
            return ftt


solve_lwpm_birthday(f2, 3)
solve_lwpm_birthday(f3, 3)


def solve_lwmp_bkz(f, n=700):
    H, n, k = lwmp_parity_check(f, n)
    xb = []
    t = 1
    for i in range(n):
        xb.append(t)
        t = t * x
    xb = vector(xb)

    rr = H.right_kernel_matrix().change_ring(ZZ).BKZ()

    g = rr[0] * xb
    assert g % f == 0
    g = g // list(g)[-1][1]
    assert g % f == 0
    return g


solve_lwmp_bkz(f2)
solve_lwmp_bkz(f3)

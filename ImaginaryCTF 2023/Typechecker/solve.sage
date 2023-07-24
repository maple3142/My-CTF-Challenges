R = Zmod(67)
chrs = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{_-!}"
c1 = "eZ!gjyTdSLcJ3{!Y_pTcMqW7qu{cMoyb04JXFHUaXx{8gTCIwIGE-AAWb1_wu32{"
c2 = "HuuMKaxLVHVqC6NSB1Rwl2WC1F7zkxxrxAuZFpPogbBd4LGGgBfK9!eUaaSIuqJK"
sz = 8
A = matrix(R, sz, sz, [chrs.index(c) for c in c1])
B = matrix(R, sz, sz, [chrs.index(c) for c in c2])

xs = PolynomialRing(R, "x", sz * sz).gens()
X = matrix(sz, sz, xs)
Z = A * X - X * B
M, _ = Sequence(Z.list()).coefficient_matrix()
ker = M.dense_matrix().right_kernel_matrix()
print(ker)
sol = (
    ker[:, :5]
    .augment(ker[:, -3:])
    .solve_left(vector(R, [chrs.index(c) for c in "ictf{" + "}00"]))
)
print("".join([chrs[x] for x in sol * ker]))

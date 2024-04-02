#!/usr/bin/env sage
import os

R = PolynomialRing(ZZ, ["x", "y", "z"])
x, y, z = R.gens()
f = x ^ 3 + y ^ 3 - z ^ 3
x, y, z = map(
    R, input("Enter your FLT counter example as comma separated values: ").split(",")
)
assert x > 0 and y > 0 and z > 0, "bad :("
assert f(x, y, z) == 0, "FLT is not wrong!"
print(
    os.environ.get("FLAG", "jctf{red_flags_and_fake_flags_form_an_equivalence_class}")
)

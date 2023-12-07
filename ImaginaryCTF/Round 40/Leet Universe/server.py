#!/usr/bin/env python3
from math import gcd
import os

flag = os.environ.get(
    "FLAG", "jctf{red_flags_and_fake_flags_form_an_equivalence_class}"
)

x = int(input("x = "))
g = gcd(x**13 + 37, (x + 42) ** 13 + 42)
print(flag[:g])

# Unchanged

* Round: 28 (2022/11)
* Category: Reverse
* Points: 100
* Solves: 16

## Description

Why does this flag checker sometimes take so long?

## Solution

The `check` function will become infinite loop when the input is the fixed point of `f(x)=a*x+b (mod 2^64)`, and thus keep the checking result not being overridden until timeout. So you can extract those `a` and `b` numbers for each check and solve for `f(x)=x (mod 2^64)` to get flag.

```python
from pwn import ELF
import struct

elf = ELF("./chall")
sz = 4 + 4 + 8 + 8 + 8
for i in range(144 // 8):
    data = elf.read(elf.sym["checks"] + i * sz, sz)
    _, _, a, b, _ = struct.unpack("<IIQQQ", data)
    # a*x+b=x
    # (a-1)*x+b=0
    # x=-b/(a-1)
    x = pow(a - 1, -1, 2**64) * -b % 2**64
    print(x.to_bytes(8, "little").decode(), end="")
```

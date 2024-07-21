# notitle

* Category: Crypto
* Score: 498/500
* Solves: 5

## Description

The keys are obfuscated by a weird magic operation.

## Solution

The `magic_op` computes the first kind of Chebyshev polynomials, and we can observe that either `magic_op(x, p + 1) == 1` or `magic_op(x, p - 1) == 1` for random `x`. This implies it corresponds to some group structure.

First we have to obtain the `h`, which means it corresponds to some kind of discrete logarithm problem, and it is doable as `p - 1` and `p + 1` have a large smooth part. Either implementing Pohlig-Hellman algorithm yourself or find a homomorphism to `GF(p^2)` and call `discrete_log` would work.

Once `h` is obtained, for each obfuscated key we can check which group does it belongs and try to decrypt it. The problem is that `h = 4 * large_number`, so the decryption might not be unique. But we know that the sum of the correct ones is the real key, which is just 128 bits -> LLL!

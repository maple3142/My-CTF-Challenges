# Pedantic

* Category: Crypto
* Score: 268/500
* Solves: 25

## Description

You can never be too pedantic!

## Overview

In this challenge, players have to prove to the server that they know the secret key (hash of the flag) to a public key using a NIZK proof of ECDLP. The NIZK is multiround, and the fiat shamir hashes the commitments to $\mathbb{F}_q$ and sums them up to a seed. The seed is used as a input to a LCG to generate the challenges for each rounds. The target is to forge a proof containing more than 42 rounds.

## Solution

> Note. This original intended solution of this challenge is the same as the **Paranoid** challenge, but a much easier solution exists here due to a mistake.

First, the public key is not directly given, but we can use the provided 10-rounds proof to compute the public key. Just use the proof to compute the challenges $c_i$ for each round, then the public key is $Y=c_i^{-1} (Gz_i-(Gr_i))$.

How to forge a proof in this challenge? The vulnerability is in the `hash_points_to_scalars` function:

```python
def hash_points_to_scalars(pts: list[Point], n: int):
    s = sum([hash_point(pt) for pt in pts]) % q
    ret = []
    for _ in range(n):
        ret.append(s)
        s = (1337 * s + 7331) % q
    return ret
```

After the sum $s$ it computed, it is used as the seed of a LCG to generate the challenges. Since LCG have a fixed point $c=\frac{-b}{a-1}$ where $ac+b=c$, if we set $s=c$ then **all the challenges $c_i$ will be equal** to $c$.

Can we generate the commitments $(Gr)_i$ such the sum of their hashes is equal to $c$? Yes, simply samples some $z_i$ can compute the corresponding $(Gr)_i=Gz_i-Yc_i$, and hash them to $h_i$. Then we apply LLL to find a small positive combination $a_i$ of $h_i$ that sums to $c$ over $\mathbb{F}_q$.

For each $i$, we duplicate $z_i$ and $(Gr)_i$ for $a_i$ times, then we have a proof with $\sum a_i$ rounds. The sum of $h_i$ is $c$, so all the challenges $c_i=c$, thus the proof is valid.

See [solve.py](./exp/solve.py) for details.

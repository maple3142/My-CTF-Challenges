# ZKPoF

* Category: Crypto
* Score: /500
* Solves: 

## Description

I will use zero-knowledge proof to prove the knowledge for the factorization of n=p*q, so you wouldn’t be able to learn anything from it.

## Overview

It implements a zero knowledge proof protocol from [Short Proofs of Knowledge for Factoring](https://www.di.ens.fr/~stern/data/St84.pdf). The server generates an $n=pq$ and act as a prover at most $311$ times, then the client have to act as the prover to prove $13$ times to get the flag.

## Solution

The intended vulnerability of this challenge is quite subtle:

```python
def zkpof(z, n, phi):
    # I act as the prover
    r = getRandomRange(0, A)
    x = pow(z, r, n)
    e = int(input("e = "))
    if e >= B:
        raise ValueError("e too large")
    y = r + (n - phi) * e
    transcript = {"x": x, "e": e, "y": y}
    return json.dumps(transcript)
```

It is apparently that the server is missing the check that $e \ge 0$, but since `zkpof_verify` checks that $0 \le y \land y < A$ so you can't leak $n-\varphi(n)$ by sending $e<-A$. However, if you try to set $e$ to be a very big negative number, you may see the following exception:

```
Error: Exceeds the limit (4300 digits) for integer string conversion; use sys.set_int_max_str_digits() to increase the limit
```

This is because CPython fixed a possible DoS of `int <-> str` conversion in [CVE-2020-10735: Prevent DoS by large int<->str conversions](https://github.com/python/cpython/issues/95778), which restrict the default maximum decimal digits allowed for conversion is 4300 digits. So trying to convert a number `n` that `abs(n)>=10**4300` will result in an exception.

So we can binary search that and recover the top $311$ bits of $n-\varphi(n)=p+q-1$ as $l$. Then $s=\lfloor \sqrt{l^2-4n} \rfloor$ would be an approximation of $p-q$ (or $q-p$), so $t=(l+s)/2$ is an approximation (~311 bits) of either $p$ or $q$.

This means we can apply coppersmith to factor $n$ and complete the `zkpof_reverse` to get the flag.

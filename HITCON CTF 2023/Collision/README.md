# Collision

* Category: Crypto
* Score: 327/500
* Solves: 11

## Description

All you need is to find a hash collision for this, pretty simple right?

## Overview

You need to do chosen-prefix collision attack on CPython 3.11's builtin hash function, which is SipHash-1-3. `PYTHONHASHSEED` is set to a random 32-bit integer.

It is necessary to find 8 collisions in 240 seconds to get the flag.

## Solution

First, [CPython's SipHash-1-3](https://github.com/python/cpython/blob/3.11/Python/pyhash.c#L485-L490) is a keyed hash function, which is seeded by `PYTHONHASHSEED` if present. From [here](https://github.com/python/cpython/blob/3.11/Python/bootstrap_hash.c#L565), we know that it use `PYTHONHASHSEED` as an initial state to a [LCG](https://github.com/python/cpython/blob/3.11/Python/bootstrap_hash.c#L414-L427) with modulus $2^{32}$, and extract 23..16 bits to generate key bytes.

Apparently, only the lower 24 bits of `PYTHONHASHSEED` matters. We can verify this by:

```python
> python -c 'print(567 + 2**24)'
16777783

> PYTHONHASHSEED=567 python -c 'print(hash(b"a"))'
3702142049416087210

> PYTHONHASHSEED=16777783 python -c 'print(hash(b"a"))'
3702142049416087210
```

What this implies is that can we can brute-force the lower 24 bits of `PYTHONHASHSEED` to compute the hash of given prefix, then do an inverse lookup to find the key. Implementing this in C and this part would only take negligible amount of time.

Once you have the key, SipHash-1-3 becomes a regular hash function. But as far as I know, there is no known collision attack on SipHash-1-3 even if the key is known. So the best we can do is birthday attack, which is $\sqrt{2^{64}}=2^{32}$.

A naive MITM would take a lot of space, so we need to use cycle-finding (Pollard's rho) to find a cycle, which can be turned into a collision. When implemented in single-threaded C, it would take over a minute (on my PC) to find a collision, which is not fast enough to solve the challenge.

An obvious optimization is to parallelize it, but it is not obvious how to spread the cycle finding into multiple threads. With some Google searches, it is easy to know there is a parallelized version of Pollard's rho called Pollard's lambda.

In Pollard's lambda, there is a thing call **distinguished points**, which is a set of points satifying some condition. (e.g. `hash & MASK == 0`) Instead of cycle finding, we start from some random points and repeated apply the hash until finding a distinguished point, and store a tuple of `(start, end, length)` called **trace**.

Once we have enough traces, it is possible to have multiple traces ending at the same distinguished point. In this case, it would looks like the math symbol $\lambda$ (two traces merge into one). So we can take those two traces and evaluate the longer one until it reaches the same length as the shorter one, then a collision can be found by evaluating both traces forward.

Implementing this in C++, it takes on average 10 seconds to find a collision (on my PC), which is fast enough to solve the challenge.

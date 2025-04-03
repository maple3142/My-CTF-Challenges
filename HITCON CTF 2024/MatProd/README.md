# MatProd

* Category: Crypto
* Score: 500/500
* Solves: 1

## Description

A zero-day challenge for a crypto paper?!

## Overview

The target is to break the two public-key cryptosystem construction from [iacr:2023/1745](https://eprint.iacr.org/2023/1745): Direct and Alternating.

## Solution

The writeup here would use the same notation as the paper, so it is recommended to read and understand the paper first.

### Breaking Direct

The ciphertext matrix $M$ defined by:

$$
M = \prod_{i=0}^{k-1} \bar{A}_{\sigma(i)} = E \left( \prod_{i=0}^{k-1} A_{\sigma(i)} \right) E^{-1}
$$

We know that trace is not changed by conjugation, so we try to multiply $M$ by every inverse of $\bar{A}_i$ and check if the trace getting smaller, hence recovered the entire permutation $\sigma$.

See [solve_direct.py](./solution/solve_direct.py) for the solver for direct construction.

### Breaking Alternating

The ciphertext matrix $M$ defined by:

$$
M = \prod_{i=0}^{k-1} \bar{A}_i^{m_i} = \prod_{i=0}^{k-1} E_i A_i^{m_i} E_{i+1}^{-1} = E_0 \left( \prod_{i=0}^{k-1} A_i^{m_i} \right) E_k^{-1}
$$

where $m_i$ is the binary digits of the plaintext $m$.

We know that every $A_i$ (without bar) have small entries, so their trace are small too. The trace of their product are small too.

Also, using the cyclic property of trace, we see that:

$$
\mathop{\text{tr}}(\prod_{i=0}^{k-1} A_i^{m_i}) = \mathop{\text{tr}}(M E_k E_0^{-1})
$$

There is also an interesting property of the trace of a product of matrices, which is:

$$
\mathop{\text{tr}}(AB) = \mathop{\text{flatten}}(A) \cdot \mathop{\text{flatten}}(B^T)
$$

where $\mathop{\text{flatten}}$ is a function that flatten a $n \times n$ matrix into a $n^2$ dimension vector. (i.e. SageMath's `vector(mat.list())`)

Combining them, we have:

$$
\mathop{\text{tr}}(\prod_{i=0}^{k-1} A_i^{m_i}) = \mathop{\text{flatten}}(M) \cdot \mathop{\text{flatten}}((E_k E_0^{-1})^T)
$$

which is small.

Note that it also holds if we multiply the correct inverse of $\bar{A}_i^b$ to $M$, and any incorrect inverse of $\bar{A}_i^b$ to $M$ will suddenly increase the trace a lot.

So my idea is to brute force some bits for the start and end of the $m_i$ (e.g. $a$ bits from front and $b$ bits from end), and multiply all the inverse to $M$ and resulting in bunch of $M'_j$.

Then we generate some random partial ciphertext $M_r$ that have same rank with $M'_j$ (i.e. start and ends with same index like $a$ to $k-b$). For each $M_r$, flatten it and put it into a column of a lattice $L$, then reduce it modulo $p$. Take the shortest non-zero vector $v$ from the reduced basis and solve for $t$ that satisfy $tL=v$, and $t$ is a vector that can be seen as (quasi-)equivalent to $\mathop{\text{flatten}}((E_{k-b} E_a^{-1})^T)$.

Finally, for each $M'_j$ we compute $s_j = t \cdot \mathop{\text{flatten}}(M'_j)$, and if there is a $s_j$ that is significantly smaller than the rest ($\approx p$) then it is the correct guess. Simply repeat these steps iteratively until we get the entire $m$ and we are done.

The reason that $t$ can only be seen as a (quasi-)equivalent to the flattened binding matrix is because any entries in the product of $A_i^{m_i}$ is also small (even slightly smaller than the trace), and every one of them can also be written as a linear combination of the flattened binding matrix. Therefore the $s_j$ values we get is also not the trace that we expect, but some randomly small linear combination of the matrix entries.

See [solve_alternting.py](./solution/solve_alternting.py) for the solver for alternating construction.

> If you find my explanation to hard to understand, read [this writeup](https://blog.tanglee.top/2024/07/15/HITCON-CTF-2024-Qual-Crypto-Writeup.html#matprod) by others instead. It did a really good job at explaning my attack then this, especially on the alternating one XD.

### Get Flag

Just run both solver to get the plaintext for both challenge, and execute:

```bash
python solve.py <direct-plaintext> <alternating-plaintext>
```

to decrypt the flag.

See [solve.py](./solution/solve.py).

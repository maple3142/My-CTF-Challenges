# EZRSA

* Category: Crypto
* Score: 327/500
* Solves: 11

## Description

I am out of ideas, so why not just make a challenge from a [random paper](https://eprint.iacr.org/2023/1299).

## Overview

This challenge is based on [A New RSA Variant Based on Elliptic Curves](https://eprint.iacr.org/2023/1299). A keypair in generated at start, then you have arbitrary access to encryption and decryption oracle. The goal is to recover the private key to be able to pass the decryption challenge.

## Solution

### Recovering $n$

Since decryption oracle is just computing $d \times (x, y)$ on elliptic curve $E: y^2=x^3+ax$. Decrypt some random points and get $n$ from gcd.

### Recovering $d$

Since the `compute_u` function misuses a `else:` branch instead of actually checking $a$ as described in the paper, it is possible to make it decrypt with $a=0$ by setting $y^2 = x^3$. So we are now working on a curve $E: y^2 = x^3$.

Apparently, the curve is singular, and we know there is a map

$$
\phi: (x,y) \rightarrow \frac{x}{y}
$$

which goes from $E(\mathbb{Z}_n)$ to the additive group $\mathbb{Z}_n$, so DLP is trivial.

In the easiest case, $d$ can be computed by $x/y \mod{n}$ where $x, y = \operatorname{decrypt}(1, 1)$.

### Recovering $e$

We know $ed \equiv 1 \pmod{\phi}$, where $\phi=(p+1+2v_p)(q+1+2v_q)$. In this equation, we know $e \approx n^{1/8}$ and $2v_p \approx \sqrt{p}$, $2v_q \approx \sqrt{q}$. The latter implies $\phi-n \approx n^{3/4}$.

Only $d,n$ are known here, and $e$ are small. If you swap the symbol of $e,d$, it is easy to see this is actually similar to Wiener/Boneh-Durfee attack. So we can use the same method to recover $e$.

What I did here is to see that $ed=k \mod{n}$, where $k \approx en^{3/4}$, so we can setup a lattice like this:

$$
\begin{bmatrix}
d & 1 \\
n & 0
\end{bmatrix}
$$

Balance the columns property and LLL then we can recovery $e$ easily.

### Factoring $n$

We know that $ed-1=t\phi$, and $\phi \approx n$. So we have $t=\lfloor (ed-1)/n \rfloor$, then $\phi=(ed-1)/t$.

Since $\phi$ is the order of $E(\mathbb{Z}_n)$ for $1/4$ of $a$ in $y^2=x^3+ax$, we just choose random curves and random points, and multiply it by $\phi$ until we get `ZeroDivisionError`, then we will get $p, q$ by computing gcd.

> This ECM-like method already appeared in [HITCON CTF 2022 - Chimera](../../HITCON%20CTF%202022/Chimera/README.md) too.

### Recovering $u_p, v_p, u_q, v_q$

If you understand what the original is trying to do, you will know that $2U_p, 2U_q$ are the trace of $E(\mathbb{F}_p), E(\mathbb{F}_q)$ respectively. So by choosing $a$ properly, it is easy to get $u_p, v_p, u_q, v_q$ by telling sage to compute the trace.

Once you have all these, it is easy to decrypt anything you want, so you can pass the challenge to get the flag.

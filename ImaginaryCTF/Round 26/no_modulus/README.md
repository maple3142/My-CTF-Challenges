# No modulus

* Round: 26 (2022/09)
* Category: Crypto
* Points: 200
* Solves: 1

## Description

Who needs modulus anyway?

## Solution

First let `es` be $e_i$ and `cs` be $c_i$.

Suppose you found $a_i$ such that $\sum_{i=0}^{n-1} a_i e_i = 0$, then the following equation will be true:

$$
\prod_{i=0}^{n-1} c_i^{a_i} = m^{e_i a_i} = m^0 = 1 \pmod{n}
$$

So finding 2 such $a_i$ and we can recover $n$ with gcd, but since we are computing the power in ring of integers so we need to **make them small**. And LLL can be used here to find some small linear combinations for that:

$$
L=
\begin{bmatrix}
K e_0 & 1 \\
K e_1 & & 1 \\
\vdots & & & \ddots \\
K e_{n-1} & & & & 1
\end{bmatrix}
$$

The first column of first few vectors in the reduced basis of $L$ will be $0$ when $K$ is large enough, and the remaining columns will *captures* those $a_i$ for us.

Also, $a_i$ will have some negative entries in it, so $\prod_{i=0}^{n-1} c_i^{a_i}$ will be a rational number. Denote it as $x \over y$ then we will have this:

$$
\begin{aligned}
\frac{x}{y} &\equiv 1 \pmod{n} \\
\frac{x}{y} - 1 &\equiv 0 \pmod{n} \\
x-y &\equiv 0 \pmod{n}
\end{aligned}
$$

So $\gcd(x_0-y_0, x_1-y_1)$ will probably be $n$.

After getting $n$, the flag can be easily decrypted with common modulus attack.

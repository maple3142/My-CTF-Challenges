# Chimera

* Category: Crypto
* Score: 400/500
* Solves: 4

## Description

The Chimera, also Chimaera, according to Greek mythology, was a monstrous fire-breathing hybrid creature, composed of different animal parts from Lycia, Asia Minor. It is usually depicted as a lion, with the head of a goat protruding from its back, and a tail that might end with a snake's head.

## Overview

Please just read the code directly, it is a bit hard to explain clearly here.

## Solution

### Recovering $n$

`chimera` is a list of points on $E(\mathbb{Z}/n^2\mathbb{Z})$, where each point $(x, y)$ satisfies the following equation:

$$
y^2 \equiv x^3 + ax + b \pmod{n^2}
$$

With 3 points we can eliminate the unknown $a, b$ to get some multiples of $n^2$, so taking gcd of them recovers $n^2$ and thus $n$.

> A nice explicit formula for this is given in this [writeup](https://hackmd.io/@mystiz/uiuctf-2020-nookcrypt#Part-I-Recovering-the-curve-parameters-in-a-stupid-way)

### Recovering $a, b$

Once you have $n$, it is easy to solve for $a, b$ from 2 points.

### Factoring $n$ with `gift`

`gift` is defined as $\\#E(\mathbb{F}_p) \times \\#E(\mathbb{F}_q)$, so any points on $E(\mathbb{Z}/n\mathbb{Z})$ multiply by `gift` will be point at infinity.

If you try to divide `gift` by some small factors then it might be and multiple of $\\#E(\mathbb{F}_p)$ but not $\\#E(\mathbb{F}_q)$, and multiply it to a point on $E(\mathbb{Z}/p\mathbb{Z})$ will give you an error when computing the inverse. So you can use gcd to get a non-trivial factor of $n$.

Actually, this is the core idea of [Lenstra elliptic-curve factorization](https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization).

### Recovering $G$

From the code we know that $G_x$ and $G_y$ are less than $2^{256}$, which is very small compared to $n^2$, so we can find them with LLL or Coppersmith's method.

### Solving ECDLP

Once you have $G$ you may want to solve ECDLP for each point in `chimera` with respect to $G$.

Proposition 19 of [The group structure of elliptic curves over Z/NZ](https://www.researchgate.net/publication/344971478_The_group_structure_of_elliptic_curves_over_ZNZ) gives a very nice explicit group homomorphism from $E(\mathbb{Z}/p^e\mathbb{Z})$ to $\mathbb{Z}/p^{e-1}\mathbb{Z}$, so we can solve ECDLP modulo $p^{e-1}$.

So you will solve ECDLP in $E(\mathbb{Z}/p^2\mathbb{Z})$ and $E(\mathbb{Z}/q^2\mathbb{Z})$ respectively, and then use CRT to get the answer.

Per @rkm0959, you can also solve ECDLP without factoring $n$ too. It uses the same proposition 19 by simply replacing that $q$ with `gift` and it actually works correctly here.

### Solving A variant of Hidden Subset Sum Problem

Let the ECDLP results of each points in `chimera` with respect to $G$ be $b_i$, and the `randint(1, n)` in `[randint(1, n) * lion_head for _ in range(16)]` be $x_i$, then we will get the following system:

$$
A
\begin{bmatrix}
x_0 \\
x_1 \\
\vdots \\
x_{15}
\end{bmatrix}=
\begin{bmatrix}
b_0 \\
b_1 \\
b_2 \\
\vdots \\
b_{62} \\
b_{63}
\end{bmatrix}
$$

where $A$ is a $64 \times 16$ matrix with entries in $[0, 256)$.

Suppose $x_i$ are known and $A$ is a binary matrix, we call this Subset Sum Problem (multiple instances), which can be solved with LLL when the density is high enough.

When $A$ is a binary matrix and $x_i$ are unknown, it is called Hidden Subset Sum Problem. If you know this term then it is easy to find [A Polynomial-Time Algorithm for Solving the Hidden Subset Sum Problem](https://eprint.iacr.org/2020/461.pdf).

Implement the **Nguyen-Stern Algorithm** as described in the paper, and 
modify their greedy algorithm described in Appendix D to fit $A$ having entries in $[0, 256)$ solves the problem.

That greedy algorithm is meant to turn vectors in range $[-1,1]$ into $[0,1]$, so you will need to modify it to turn vectors in range $[-256, 256]$ into $[0, 256)$. But I couldn't get that work, so I ended up bruteforce some random combinations of vectors instead, and it work surprisingly well.

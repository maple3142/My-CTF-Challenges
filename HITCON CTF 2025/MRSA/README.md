# MRSA

* Category: Crypto
* Score: 350/500
* Solves: 8

## Description

An obvious generalization of RSA, what could go wrong?

## Overview

$M$ is a $k \times k$ matrix where $k=16$, and each element is a byte (0-255). The ciphertext $C=M^e \pmod{n}$ is given, and $n=pq$ is a RSA semiprime. The target is to recover $M$ given only $C$ and $e$ ($n$ is not provided).

## Solution

One of the most important observation required by this challenge is that $M$ commutes with $C$ over $\mathbb{Z}_n$ (i.e. $MC=CM$). This is trivial in the original RSA, but it provides non-trivial info in the matrix ring.

Moreover, the matrices commutes with $C$ form a subspace with basis $\{C^0,C^1,\cdots,C^{k-1}\}$ assuming that $C$ has distinct eigenvalues. This means that $M=a_0C^0+a_1C^1+\cdots+a_{k-1}C^{k-1}$ holds for some unknown coefficients $a_i$ over $\mathbb{Z}_n$. So if $n$ is known, we can obtain a reduced basis LLL, which would contain $I$ and $M-tI$ for some small integer $t$. But we don't know $n$ here, so we need to find other way to approach this.

Reverse the role of $M$ and $C$, we can see that $C=b_0M^0+b_1M^1+\cdots+b_{k-1}M^{k-1}$ also holds over $\mathbb{Z}_n$, which is equivalent to:

$$
C=b_0M^0+b_1M^1+\cdots+b_{k-1}M^{k-1}+nK
$$

where $K$ is a $k \times k$ integer matrix.

We can see that the element of $M^0,\cdots,M^{k-1}$ are all pretty small compared to $n$, and the unknown coefficients $b_i$ are approximately equal to $n$. Therefore, the element of $K$ is approximately same magnitude as $M^{k-1}$, which is still small enough. So the problem here is similar to AGCD or HSSP, we can apply orthogonal lattices to find $M$. Of course, the solution contains both $I$ and $M-tI$ for some small integer $t$, so a very small bruteforce is still needed. See my solver [solve.py](./exp/solve.py) for details.

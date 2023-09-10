# Share

* Category: Crypto
* Score: 222/500
* Solves: 47

## Description

I hope I actually implemented Shamir Secret Sharing correctly this year. I am pretty sure you won't be able to guess my secret even when I give you all but one share.

## Overview

The server have a 256-bits secret and for each $(p, n)$ input, it will use Shamir Secret Sharing in $\mathbb{F}_p$ to split the secret into $n$ shares, and give you $n-1$ of them.

## Solution

The vulnerability is how it generates the polynomial coefficient: `getRandomRange(0, self.p - 1)`. Reading the docs, we know `getRandomRange(a, b)` generates a number between $[a, b)$, so the coefficient will be in $[0, p-2]$. In other words, the coefficient will never be $p-1$.

So if we define a polynomial $f(x)$ as:

$$
f(x)=-x^{n-1}+g(x)
$$

Since $\deg g(x)=n-2$, we can do a simple substitution to interpolate an unique $g(x)$ using our $n-1$ shares. Since the coefficient of $x^{n-1}$ is $-1$, this means $f(0)$ represents an **impossible value** of the secret modulo $p$. By collecting more and more impossible values, we know the only possible value of the secret modulo $p$.

Doing the same for several $p$ such that the product of them is greater than $2^{256}$, we can recover the secret using CRT.

Note that the server has a timeout of 30 seconds, so you need to deal with network latency by querying a bunch of $(p, n)$ pairs at the same time.

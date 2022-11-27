# BabySSS

* Category: Crypto
* Score: ?/500
* Solves: ?

## Description

I implemented a toy [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) for fun. Can you help me check is there any issues with this?

## Overview

The challenge have a polynomial $f(x)$ with $\deg{f(x)} = 128$, and each coefficient is a 64 bit positive integer. Each shares is a pair of $(x, f(x))$ with $x$ being a random 16 bit positive integer, only $8$ shares are given. The objective is to recover the secret $f(0x48763)$.

## Solution

First we know

$$
y = f(x) = a_0 + a_1 x + a_2 x^2 + \cdots
$$

So for each shares $(x_i, y_i)$ we can derive an equation $y \equiv a_0 \pmod{x}$, and use [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) to get $a_0 \mod{\operatorname{lcm}(x_0, x_1, \cdots)}$.

With some testing we can see the LCM of those $x$ is much bigger than $2^{64}$, so we already know the exact value of $a_0$ (a.k.a. constant term of $f(x)$).

By doing the same with $(x_i, (y_i - a_0) / x_i)$ we can get $a_1$. Repeat this to recover all the coefficients and we can get the secret.

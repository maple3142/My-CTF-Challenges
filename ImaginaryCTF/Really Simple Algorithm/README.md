# Really Simple Algorithm

* Round: 15 (2021/10)
* Category: Crypto
* Points: 150
* Solves: 5 (Include me)

## Description

I hide my flags with a really simple algorithm, and I'll *continue* to do so until you can retrieve the flag!

## Overview

The challenge is RSA with 3 primes $p,q,r$, each of them is 512 bit prime. And a special decimal value $k=\frac{p}{48763q-r}$ is provided with some precision loss.

## Solution

The decimal value of $k$ is provided with a precision of 320 digits. If we try to represent it as a fraction denoted as $k'=\frac{a}{b}$, we know that:

$$
|k' - k| < 10^{-320} < 2^{-1063}
$$

It looks close enough, perhaps we can approximate the correct $k$ with [Continued fraction](https://en.wikipedia.org/wiki/Continued_fraction) right? There is a theorem (Legendre's theorem in Diophantine approximations) states that if

$$
|x-\frac{a}{b}| < \frac{1}{2b^2}
$$

then $\frac{a}{b}$ is a convergents of $x$.

In this challenge, $b=48763q-r \approx 2^{527.5}$. So $|k'-k| < \frac{1}{2b^2}$ is true, therefore $k$ must be a convergents of $k'$. You just need to try all of them and see which convergents' numerator divides $n$, then you will know it is $p$.

Now you know $p$, you should be able to get $m \bmod{p}$ without factoring the remaining $qr$. But it is not enough to decrypt the flag as I appended the sha256 specifically for making $m > p$, so you still need to factor $qr$ to solve this challenge.

Factoring $qr$ with $48763q-r$ is pretty similar to factoring $pq$ given $p+q$, you just need to modify the polynomial used a bit.

$$
(x-48763q)(x+r)=x^2-(48763q-r)x-qr
$$

So you can solve the quadratic equation to get $q,r$ now, then sue it decrypt the flag.

My solution script is [solve.sage](solve.sage), there are more details in it.

Flag: `ictf{approximating_and_solving_equations}`

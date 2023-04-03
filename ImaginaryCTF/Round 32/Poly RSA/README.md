# Poly RSA

* Round: 32 (2023/03)
* Category: Crypto
* Points: 150
* Solves: 6

## Description

As we all know, finding a root for a polynomial modulo n requires knowing the factorization of n, so it should be as safe as RSA!

## Solution

If $f(x)=p(x)^2*q(x)$, then $f'(x)=2p(x)p'(x)q(x)+q'(x)p(x)^2=p(x)r(x)$, so $\gcd(f(x), f'(x))$ will most probably be $p(x)$.

Computing the gcd of polynomial with degree 65537 with the naive way takes several hours on an average computer, so you are supposed to use half GCD algorithm. There is an [existing implementation](https://github.com/rkm0959/rkm0959_implements/tree/main/Half_GCD) that you can copy from.

After computing the gcd we get $p(x)=(x-m_1)(x-m_2)$, and $m_2$ can be found by coppersmith as $m_2<2^{256}$, then recovering $m_1$ is easy.

Another way is to notice the fact that $(x-m_1)(x-m_2)=x^2-(m_1+m_2)x+m_1 m_2$, where $m_1$ is flag appended by many random bytes. Since $m_2$ is small so $m_1+m_2$ won't clobber high bits of $m_1$, therefore we can expect `bytes_to_long(m1_plus_m2)` to reveal the flag.

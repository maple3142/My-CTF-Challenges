# pacap

* Category: Crypto
* Score: 500/500
* Solves: 2

## Description

The "capac" challenge from Crypto CTF 2024 can be directly solved by factorizing the modulus, but is it still solvable if the modulus is much larger?

Original challenge is made by [@factoreal](https://x.com/refactoreal).

## Solution

Taking the resultant of curve equation and $x^3+cy^3=1$ result in a 6-degree polynomial $f(x,y)$. By, substituting $u=1-x^3$, $v=y^3$, $f$ can be written as a polynomial in $u$ and $v$, with only $u^2$, $uv$ and $v^2$ terms. Note that $x,y$ are pretty small compared to the modulus, so $u,v$ are still small.

Applying coppersmith method only find the trivial root $(0, 0)$, so I take the gcd of the first two short polynomials and it result in a polynomial in the form of $au+bv$. Since `a,b` are small, we can assume that $v=k*a$ for some small $k=gcd(u,v)$ (up to sign) and recover the flag from $u$ and $v$.

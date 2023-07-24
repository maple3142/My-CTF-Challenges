# Sus

* Category: Crypto
* Score: 499/500
* Solves: 3

## Description

Apparently, there is something weird happening with the prime generation.

## Solution

Pick a random polynomial $f(x)=x^3+ax^2+bx+c$, and pick a random element $a$ in $\mathbb{R}=\mathbb{Z}_n[x]/f(x)$. If $f(x)$ is irreducible in $\mathbb{F}_p[x]$ then $\mathbb{K}=\mathbb{F}_p[x]/f(x)=\mathbb{F}_{p^3}$ will be a field with order $p^3-1=(p-1)(p^2+p+1)$.

We raise $a$ to the power of $n=pqr=p(p^2+p+1)r$ then $a^n$ would probably be of order $p-1$, which implies it will be in the form of $u+0x+0x^2$ in $\mathbb{K}$. This means we can take the degree 1 or 2 coefficient of $a^n$ in $\mathbb{R}$ and gcd it with $n$ to get $p$, then we can fully factor $n$ to decrypt the flag.

This is basically the same idea as Pollard's p-1 or Williams' p+1 factorization algorithm, but we are doing it in a field with higher degree.

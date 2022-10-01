# pqqp

* Round: 26 (2022/10)
* Category: Crypto
* Points: 75
* Solves: 39

## Description

Just RSA with an extra useless number that won't help you factoring it.

## Solution

$\text{pqqp}=p^q+q^p$, so $\text{pqqp} = p \pmod{q}$ and $\text{pqqp} = q \pmod{p}$ by fermat little theorem. Then by definition, $\text{pqqp} = p+xq = q+yp$ for some integers $x,y$, and it has an obvious solution $x=y=1$. Therefore $pqqp=p+q$, and it is easy to factor $n$ from $p+q$ by solving it as a quadratic equation.

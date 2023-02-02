# Power RSA

* Round: 30 (2023/01)
* Category: Crypto
* Points: 75
* Solves: 

## Description

Another boring RSA challenge

## Solution

`p=x^2+1` and `q=x^2+1` so `isqrt(n,2)` is a good approximation of `x*y`, then you get `phi(n)=x^2*y^2` so you can compute `d` to decrypt the flag.

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

with open('output.txt') as f:
    exec(f.read())

xy = gmpy2.iroot(n, 2)[0] - 1
phi = xy**2
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

@sahuang found that there is a generalization of this challenge: [A New Attack on Special-Structured RSA Primes](https://einspem.upm.edu.my/journal/fullpaper/vol13saugust/8.pdf) (Paper)

Found with keyword: **near-square RSA primes**

## Proof

Proving $n>(xy+1)^2$:

$$
\begin{aligned}
n &= (x^2+1)(y^2+1) \\
  &= x^2y^2+x^2+y^2+1 \\
  &\geq x^2y^2+2xy+1 &&\text{(AM-GM Inequality)} \\
  &= (xy+1)^2
\end{aligned}
$$

On the other way, I can't prove that $(xy+2)^2 \geq n$ always hold in general:

$$
\begin{aligned}
n &= (x^2+1)(y^2+1) \\
  &= x^2y^2+x^2+y^2+1 \\
  &\stackrel{?}{\leq} x^2y^2+4xy+4 \\
  &= (xy+2)^2
\end{aligned}
$$

But assuming $x, y$ both being a 128-bit integer, it is easy to see $x^2+y^2<4xy$ always hold by experimenting with random $x, y$.

So we know $(xy+1)^2 \leq n \leq (xy+2)^2$, therefore $\lfloor \sqrt{n} \rfloor = xy+1$.

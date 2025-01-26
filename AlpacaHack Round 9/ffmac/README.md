# ffmac

* Category: Crypto
* Score: 469/500
* Solves: 2

## Description

just a simple message authentication code based on finite fields.

## Solution

This challenge is about a custom MAC scheme based on finite field of $\mathbb{F}_{p^k}$ where $p=2^{127}-1$ and $k=16$.

The MAC function `ffmac` is defined as below:

```python
def ffmac(key, x):
    k1, k2, k3, k4, k5, k6 = key
    l, r = k1, x
    for i in range(127):
        if i % 2:
            r = r * l * k2
            l = l * l
        else:
            l = l * r * k3
            r = r * r
        l, r = r, l
    return k4 * l + k5 * r * x + k6
```

It is just a complicated way to compute $c_1 x^{2^{127}} + c_2$ where $c_1, c_2$ are some secret constants derived from the key. Notice that $2^{127}=p+1$, then the MAC function $f(x)=c_1 x^{p+1}+c_2$.

Note that the map $x \rightarrow x^p$ is a **Frobenius endomorphism** of the field, which is a linear map represented by a $k \times k$ matrix of $\mathbb{F}_p$. Therefore the coefficients of $x^{p+1}$ are quadratic polynomials of the coefficients of $x$, which is a quadratic map.

So we can collect $q={k+1 \choose 2}+k+1$ input/output pairs to solve for a $k \times q$ matrix $M$, which is equivalent to the keyed MAC function.

Forging the MAC tag for the given challenge is trivial once we have the matrix, so the only thing left is to find the AES `key` from `ffmac(mackey, key)`. Since each row of $M$ is a quadratic map, solving for the key is about finding a roots to the quadratic system.

My approach to this system is to apply groebner basis to the equations, and we can see the ideal has dimension $1$ so the solution is not unique. We can that the resulting basis contains a bunch of linear equations except one quadratic equation. Given that AES key is 16 bytes, so each element is pretty small ($0 \leq x_i < 256$), applying LLL to the linear equations results in the key we want and we can decrypt the flag.

The implementation of the strategy above is in [solve.py](solve.py).

One of the possible solutions is to apply LLL to to the quadratic system directly without groebner basis (linearization), but actually doing so would not work. The reason is that there are way too many solutions to $x^{2^{127}}=c$ as it is just squaring $x$ by $127$ times, and each squaring would have two possible roots. Having many solutions can make your desired shortest vector not being the shortest vector in the lattice so LLL would not work, and this is more problematic in the lattice based on linearization due to having more dimensions.

Changing the returned value of `ffmac` to something like `return k4 * l + k5 * r * x + x + k6` would make the make the ideal having dimension 0 so `I.variety()` would return the solution directly, and LLL on linearization lattice would work too.

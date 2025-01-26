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

## Alternative Solution

This alternative solution is based on how @soon_haari solved this challenge with some simplification from me. See [solve2.py](solve2.py) for the implementation.

The idea is pretty simple. First observe that the MAC function is $c_1 x^{2^{127}} + c_2$ where $c_1, c_2$ are some secret constants derived from the key. So we can use just 2 input/output pair and solve for $c_1, c_2$ directly over $\mathbb{F}_{p^k}$. So forging the MAC tag is also trivial.

To find the AES key, it is essentially same as finding a small root to $x^{2^{127}}=c$ where $c_1 c + c_2 = \text{mackey}$.

First we can find arbitrary $a$ that $a^{2^{127}}=c$ and arbitrary $b$ that $b^{2^{127}}=1$, so every possible solutions to the equation would be in the form of $a \cdot b^i$ including the key.

Since $b$ is an element with order $2^{127}=p+1$, and $p+1$ divides $p^2-1$ so we can expect $b$ would be like an element of $\mathbb{F}_{p^2}$ in some sense. That is, $b^i$ would be in the form of $a'r+b'$ for some $r$ such that $r^2+1=0$ ($a', b'$ are arbitrary).

So $\text{key}=a \cdot b^i=(a \cdot r) \cdot a'+(a) \cdot b'$ which is small, and the can be found by LLL. This is how @soon_haari solved this challenge.

For me, based on $b^i=a' \cdot r+b'$ I observed that $b^i$ would be in a linear subspace with low rank (2) of $\mathbb{F}_p^k$. Similarly, the space of $\text{key}=a \cdot b^i$ is also small. So we can construct a basis matrix to the subspace and use LLL to find a short vector to it, which is the key!

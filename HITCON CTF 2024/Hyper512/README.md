# Hyper512

* Category: Crypto
* Score: 371/500
* Solves: 6

## Description

I don’t know how to design a secure stream cipher, but a large key space should be sufficient to block most attacks right?

## Overview

This challenges implements a stream cipher base on a non-linear combination function to combine 4 LFSR, each with 128 bits of state. The target is to recover its internal state given $2^{15}$ bits of keystream.

## Solution

### Analysis

The `bit` function is defined as:

```python
def bit(self):
    x = self.lfsr1() ^ self.lfsr1() ^ self.lfsr1()
    y = self.lfsr2()
    z = self.lfsr3() ^ self.lfsr3() ^ self.lfsr3() ^ self.lfsr3()
    w = self.lfsr4() ^ self.lfsr4()
    return (
        sha256(str((3 * x + 1 * y + 4 * z + 2 * w + 3142)).encode()).digest()[0] & 1
    )
```

We know that $x,y,z,w$ are just LFSR combined with itself, which may or may not have a different feedback polynomial, but they are still 128 bits LFSR that we can discuss later. The important thing is about how it combines $x,y,z,w$ to output.

Construct its truth table and we can analyze it with sage, and its algebraic normal form is:

$$
f(x,y,z,w)=x*y*z+x*y*w+x*z*w+y*w+y+z
$$

We can try to see if $f(x)$ correlates with any of $x,y,z,w$. Writing some code and we can see $f$ correlates with $x,y,z,w$ with probability $0.5,0.625,0.625,0.375$ respectively. So correlation attack is possible.

But every LFSR have 128 bits of state, naive correlation attack would require a $2^{128}$ bruteforce as a minimum, which is not feasible. So we have to use the **Fast Correlation Attack**, and there are a few relevant resources about it:

* [Fast correlation attacks on certain stream ciphers](https://link.springer.com/article/10.1007/BF02252874)
* [Fast Correlation Attacks: Methods and Countermeasures](https://iacr.org/archive/fse2011/67330055/67330055.pdf)  (This is the easiest one to understand imo)
* [A Fast Correlation Attack Implementation](https://projects.cs.uct.ac.za/honsproj/cgi-bin/view/2011/desai.zip/crypto_desai/index.html)

It is recommended to read them yourself, but I would do a brief explanation on how it works here.

### Fast Correlation Attack

> The notation here follows "Fast Correlation Attacks: Methods and Countermeasures".

For a (binary) LFSR with a keystream $a_j$ and a feedback relation $a_j=a_{j-1}+a_{j-3}$, we can see that these equations are always true:

$$
\begin{aligned}
a_{j-3} + a_{j-1} +& a_j = 0 \\
a_{j-2} +& a_j + a_{j+1} = 0 \\
& a_j + a_{j+2} + a_{j+3} = 0
\end{aligned}
$$

that is, its feedback equations and its shifts.

Also, we can also square it to get some equations that always hold:

$$
\begin{aligned}
a_{j-3} + a_{j-1} + a_j = 0 \\
a_{j-6} + a_{j-2} + a_j = 0 \\
a_{j-12} + a_{j-4} + a_j = 0
\end{aligned}
$$

> I am not exactly sure why it is called **square**, but I believe it comes from its feedback polynomial $f(x)=1+x^2+x^3$ and its square $f(x^2)=1+x^4+x^6$.
>
> If my understanding is correct, it actually means any $g(x)$ that is a multiple of $f(x)$ also work as a satisfying equation. And $f(x^2)=f(x)$ holds in $\mathbb{F}_2$ is a special case.

Anyway, this means from a LFSR feedback polynomial, we can obtain a bunch of relations that always hold by **shifting** and **squaring** it.

Then if we consider a LFSR with a small bias: $z_i=a_i+b_i$, $\mathbb{P}[b_i=0]=p > 0.5$  (i.e. correlation probability)

Intuitively, if one of the output bit $z_i$ have a lot of equations that holds on it, then it is likely that $b_i=0$. So we can apply all those equations to the biased stream $z_i$ and sort them by the number of equations that holds on it, and we may hope that the top $n$ $z_i$ are not biased (i.e. $b_i=0$). So we can solve a linear system to recover the internal state of the LFSR. (This describes the "Algorithm A" for FCA)

Of course, it is also possible that not all of the top $n$ $z_i$ have $b_i=0$, so we sometimes may need to bruteforce some bits and solve the linear system again, but this is inefficient. Fortunately, FCA "Algorithm B" says we can do this instead:

1. Compute a probability $p^*$ for every $z_i$ based on the number of equations that holds
2. Flip all $z_i$ with $p^* < p_{\text{thr}}$ for some threshold $p_{\text{thr}}$
3. Stop if the linear system is solvable, otherwise go back to step 1

So "Algorithm B" is a clever (and much more efficient) way to handle minimize the number of $b_i=1$.

But to be rigorous, FCA actually have to analyze the probability of the sum of those bias bits $b_i$ being zero: $s = \mathbb{P}[b^{(0)} + b^{(1)} + \cdots + b^{(t)} = 0]$, where $t$ is the number of taps of LFSR (or the number of non zero coefficients of the equation).

If you are interested in the probablity analysis, you can refer to the resources above. But the most important takeaway is that $s$ is a function of $p, t$, and $s(p, t)$ **decrease** very fast when $t$ **increase**. This means FCA is only applicable if $t$ is small, that is, the LFSR feedback polynomial have to be sparse.

But apparently, none of the masks given by the challenge have low hamming weight, so FCA can't be applied directly. Instead, we need to find a **low-weight** $g(x)$ that is a polynomial multiple to LFSR feedback polynomial $f(x)$, and this is called **Low-Weight Polynomial Multiples**.

### Low-Weight Polynomial Multiples

There are a few methods to find Low-Weight Polynomial Multiples:

* Exhaustive search
* Birthday-Paradox: Split into $\lfloor t/2 \rfloor$ and $t-\lfloor t/2 \rfloor$ and do a meet-in-the-middle search
* [Finding Low Weight Polynomial Multiples Using Lattices](https://eprint.iacr.org/2007/423.pdf) (Yes, LLL is here too)
* Reduce to find a minimum weight codeword in a linear code  (It is quite obvious if you understand the previous method)
* [A New Approach for finding Low-Weight Polynomial Multiples](https://eprint.iacr.org/2021/586.pdf)  (Haven't read)
* [Polytool](https://github.com/grocid/polytool)  (Only works for weight 4 polynomial multiple)

You can implement any of them to try to find the corresponding $g(x)$ of the LFSR in this challenge. If done correctly, you will find that `MASK1` and `MASK4` doesn't have a good enough LWPM, but `MASK2` and `MASK3` both have a weight 3 $g(x)$.

In [lwpm.sage](./solution/lwpm.sage) I implemented three of them for reference.

### Solving the challenge

While there is an existing **[implementation](https://projects.cs.uct.ac.za/honsproj/cgi-bin/view/2011/desai.zip/crypto_desai/index.html)**, I blocked it from working correctly by restricting the number of output bits to $2^{15}$.

It works with some probability if it is given more than $2^{16}$ bits of keystream, but still not guaranteed. I think it is because it is following the theorical bound described in the [original FCA paper](https://link.springer.com/article/10.1007/BF02252874), which I deliberately didn't follow in my solver (or it doesn't work on this challenge). So my intended solution actually requires player to implement FCA on their own.

Once FCA is implementated correctly, you should be able to recover the state bits of `lfsr2` and `lfsr3`.

Then if you fix $y=1 \land z=1$, the original combining function becomes:

$$
f(x,w)=x+w
$$

> There are also other useful values to fix $(y,z)$, not just $(1,1)$.

Which is the output of a 256 bits LFSR from `lfsr1` and `lfsr4`, so we call it `lfsr14`. To obtain its feedback polynomial you can either:

1. Apply Berlekamp-Massey algorithm
2. Compute `(companion_matrix(f1)^3).charpoly() * f4`  (`3` is because `3` is not a power of two, which changes the feedback polynomial of `lfsr1`)

Once you have the feedback polynomial `f14`, you can solve a linear system to recover the internal state of `lfsr14`. But to generate the exact keystream, it is still necessary to somehow *untangle* the state of `lfsr14` to `lfsr1` and `lfsr4`.

This is actually fairly simple as it is just solving another linear system constucted by the companion matrix of `lfsr1` and `lfsr4`.

Once all states are recovered, you can generate the entire keystream and decrypt the flag.

See [solve.py](./solution/solve.py) for the full solution.

### Alternative Solution: Annihilator

The combining function $f(x,y,z,w)$ has an degree 2 annihilator:

$$
g(x,y,z,w)=y*z+y+z+1
$$

However, it having $y,z$ means we have $256$ bits of unknown, and I thought applying annihilator with linearization technique requires $256+\binom{256}{2}=32896$ bits of keystream being $1$, which is not feasible given only $2^{15}=32768$ bits of keystream.

> The following solution comes from @4yn

But the analysis above is actually wrong, it actually only need $2\times 128+128\times 128=16640$ bits, and it the provided `output.txt` only gives $16368$ samples of $z_i=1$, which is insufficient.

Instead, you can ignore the linear term, so $128\times 128=16384$, and combine the known flag format we got $16399$ $z_i=1$ terms, which is sufficiently for quadratic terms. But the linear term still exist, what we can do is to guess 2 bits in the state of $y,z$ to be $1$, then linear terms can be turned into quadratic terms by multiplying the guessed bits (i.e. multiply by one).

So it has $1/4$ success probability to recover the states of $y,z$ by solving a linear system with $16368$ unknowns and $16399$ equations.

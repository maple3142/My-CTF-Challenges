# lf3r

* Category: Crypto
* Score: 408/500
* Solves: 34

## Description

LFSR's weakness comes from its linearity, so I come up with a new way to make it non-linear. Can you help me analyze it?

## Solution

Denote the stream of lsb of state as a binary vector `lfsr_lsb_stream`, there is a matrix $M_2$ over $\mathbb{F}_2$ such that $\text{lfsr\_lsb\_stream} = \text{key\_bits} \cdot M_2$ can be derived from the `MASK`.

Similarly, there is also another matrix $M_3$ over $\mathbb{F}_3$ that $\text{lfsr\_lsb\_stream} \cdot M_3 = \text{output\_ternary\_digits}$. Solving this system over $\mathbb{F}_3$ results result in a 255-dimension affine space of solutions. (i.e. $\text{lfsr\_lsb\_stream} = \text{sol} + t \cdot \text{lk}$)

Since the correct $\text{lfsr\_lsb\_stream}$ have to be binary, and the $\text{sol}$ contains ternary digits, I apply a randomized greedy algorithm to remove the presence of $2$ and it would recover the correct $\text{lfsr\_lsb\_stream}$.

Finally, solve a system over $\mathbb{F}_2$ with $M_2$ recover the key and we can decrypt the flag. See [solve.py](./solve.py) for details.

## Alternative Solution by @remy_o

Given two successive in the output $u_0, u_1$, we can see that $u_0=2n+\text{lsb}, u_1=\text{msb}+n$, so $u_0+u_1 \equiv \text{lsb}+\text{msb} \pmod{3}$, which gives many relations. This gives more than 70% bits for free, so this requires much less than 2048 bits to work.

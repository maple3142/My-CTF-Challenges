# Mobius

* Round: 27 (2022/10)
* Category: Crypto
* Points: 200
* Solves: 3

## Description

My flag checker is so inefficient that Python can't run it QAQ

## Solution

$$
f(x) = \frac{1x+3}{3x+7}
$$

is known as Mobius transformation, which can be written as a matrix 

$$
M =
\begin{bmatrix}
1 & 3 \\
3 & 7
\end{bmatrix}
$$

It is easy to verify that $f \circ f$ is same as $M \times M$, and

$$
f(\frac{x}{y}) = \frac{1x+3y}{3x+7y}
$$

is essentially

$$
\begin{bmatrix}
1 & 3 \\
3 & 7
\end{bmatrix}
\begin{bmatrix}
x \\
y
\end{bmatrix}
$$

> Source: https://math.stackexchange.com/questions/1196038/map-that-sends-a-2-times-2-matrix-to-a-mobius-transformation-is-a-homomorphism

We can see the connection between $f$ and a $2 \times 2$ matrix, so we can compute

$$
M^{-n}
\begin{bmatrix}
\text{target} \\
1
\end{bmatrix}
=
\begin{bmatrix}
u \\
v
\end{bmatrix}
$$

And $r = uv^{-1} \pmod{p}$.

But the $n=2^{2^{1337}}$ is really big, even using a fast modular exponentiation algorithm $\log(n)=2^{1337}$ is still not feasible.

The trick is to notice that $M$ is in $GL_2(F_p)$, so the group order is $\text{od} = (p^2-1)(p^2-p)$ and we have $M^n = M^{n \mod{od}}$. Since $\text{od}$ isn't much larger than $p$, we can easily get the $r$ now.

> Source of the $GL_2(F_p)$ order: https://math.stackexchange.com/questions/34271/order-of-general-and-special-linear-groups-over-finite-fields

Now we have

$$
\frac{x}{y} \equiv r \pmod{p}
$$

Muliply both sides by $y$ and remove the modulo, we get

$$
x=ry+kp
$$

Note that both $x,y$ are half of the flag, so $0 < x,y < 2^{128}$. The following lattice

$$
B=
\begin{bmatrix}
r & 1 \\
p & 0 \\
\end{bmatrix}
$$

have a short vector $(x,y)$, which can be found by LLL.

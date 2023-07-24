# Imaginary Casino

* Category: Crypto
* Score: 499/500
* Solves: 3

## Description

Immerse yourself in the captivating simplicity of Imaginary Casino, where a single game of coin flip becomes a thrilling quantum experience. Powered by a quantum-secure random number generator, every flip is truly unpredictable, ensuring an unparalleled level of fairness and excitement.

## Solution

There are two supersingular curves $C_1$ and $C_2$ connected by a known isogeny $L$ (`leet`) by $C_2=[L]C_1$, which is public parameters of the RNG.

The RNG itself has two states $l,r$ internally. Denote the initial state as $l_0, r_0$, then it will update the state when `next()` is called by

$$
\begin{aligned}
l_i&=r_{i-1} \\
r_i&=H([r_{i-1}][l_{i-1}]C_1)
\end{aligned}
$$

`next()` will return $s_i=[l_i][r_i]C_2$ as the random output, then it will drop the top 12 bits of $s_i$ and use the remaining bits as the random output.

Denote the inverse isogeny of $L$ as $\phi$, we have $C_1=[\phi]C_2$, so we can write down these equations:

$$
\begin{aligned}
l_3&=r_2 \\
   &=H([r_1][l_1]C_1)=H([l_1][r_1][\phi]C_2)=H([\phi]s_1) \\
r_3&=H([r_2][l_2]C_1)=H([l_2][r_2][\phi]C_2)=H([\phi]s_2)
\end{aligned}
$$

This means we can recover the third state $l_3, r_3$ from the first two outputs $s_1, s_2$. The expected value of your earnings when you guess the bit at random is $1/2+(-3)/2=-1$, so this basically guarantees that you can get the bits of $s_1, s_2$ consistently.

While we don't have the full state of $s_1, s_2$, you can brute force and check if it is supersingular or not. There are only approximately $\sqrt{p}$ valid public keys so it is hard to get invalid public key $s_i$ to pass the check.

The initial version of this challenge is actually just `Dual_EC_DRBG` implemented in CSIDH, but it is too easy and the second output $s_2$ is unused, so I modified it to a feistel-like construction to make use of both outputs. The is also why the flag mentions `backdoor`.

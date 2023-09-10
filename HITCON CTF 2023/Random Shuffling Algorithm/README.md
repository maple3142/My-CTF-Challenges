# Random Shuffling Algorithm

* Category: Crypto
* Score: 321/500
* Solves: 12

## Description

I think you already know what is this challenge about after seeing the challenge name :)

## Overview

There are four 1016-bit messages $m_i$ that $m_0 \oplus m_1 \oplus m_2 \oplus m_3 = \text{flag}$, and the program generates 100 RSA-1024 public keys with $e=11$.

For each public key $n_j$, it shuffles $m_i$ and encrypt all of them with $n$, with a known padding $a_{ij},b_{ij}$:

$$
c_{ij} = (a_{ij} m_{?} + b_{ij})^{11} \mod{n_j}
$$

## Solution

Suppose there is no shuffling, we can take 11 encryption and use CRT to get a polynomial $f(x)$ having $m_i$ as root when modulo $N=\prod_{j=0}^{11} n_j$, and coppersmith's method can be used to recover $m_i$. So a naive bruteforce would take $4^{11}$ invocations of coppersmith's method, which is not really feasible in 48 hours.

While we don't know $c_{ij}$ is the ciphertext of which $m_i$, but we can multiply it together like this:

$$
f_j(x) = \prod_{i=0}^{3} ((a_{ij} x + b_{ij})^{11} - c_{ij})
$$

Then we have $\forall i \in [0, 3] \, f_j(m_i) \equiv 0 \pmod{n_j}$

Now we can use CRT to get a polynomial $f(x)$ having $m_i$ as root when modulo $N=\prod_{j=0}^{99} n_j$, and coppersmith's method can be used to recover $m_i$.

Note that $\deg f(x) = 11 \times 4 = 44$, and $\log_2{N} \approx 100 \times 1024$, so you would need to use [flatter](https://github.com/keeganryan/flatter) instead of regular LLL when using coppersmith's method. My [solver](./solve.py) takes about 10 minutes to run on my PC.

This challenge is actually a modified version of the [Coppersmith’s method](https://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=76CB5B9FD566ABEFC339C4DAA16B7CFC?doi=10.1.1.107.6429&rep=rep1&type=pdf) described under **Noisy Chinese remaindering**.

# RSA-CBC v2

* Round: 27 (2022/10)
* Category: Crypto
* Points: 125
* Solves: 8

## Description

I fixed the problem of the previous attempt in mixing RSA and block ciphers, again!

## Solution

$e=9$, and for each encryption we know the iv in

$$
(\text{iv}+x)^e \stackrel{?}{\equiv} \text{ct} \pmod{n}
$$

As we know $x < 2^{8 \times 16}$ so $x$ is small enough to be recovered by applying coppersmith's method. (Because $16 \times 8 \times 9 < 2048$)

# Echo

* Category: Crypto
* Score: ?/500
* Solves: ?

## Description

A secure, cryptographically signed echo-as-a-service.

## Overview

The server generates a 512-bits RSA key pair on connection, but it doesn't give you the public key.

There are two operations available:

1. Sign the command `echo <message>` and return the RSA signature. (The message is properly escaped.)
2. Execute and given command if the signature is valid.

The target is to execute `./give me flag please` to get the flag.

## Solution

### Recovering $n$

To recover $n$, we need to find some messages $m_i$ in the form of `echo <message>` such that

$$
\prod m_i^{e_i} = 0
$$

Then the corresponding signature $s_i$ will be

$$
\prod s_i^{e_i} \equiv \prod m_i^{de_i} \equiv 0 \pmod{n}
$$

So if we can find two differents $e_i$ for given $m_i$, we can recover $n$ using GCD.

> The same idea has been used in HITCON CTF 2022 - Secret, btw.

But the problem is, how can we find such $m_i$? My solution is to pick $t$ small primes $p_j$, then find a lot of messages in the form of `echo <message>` that can be fully factored by $p_j$.

For each message $m_i$, we can write it down as:

$$
m_i = \prod_{j=1}^{t} p_j^{a_{ij}}
$$

So finding $e_i$ is equivalent to finding the kernel of $A$, which is a matrix formed by $a_{ij}$.

Note that we need to do exponentiation in $\mathbb{Z}$ to before gcd, so $e_i$ should be small. This can be done by computing the orthogonal lattice of $A$ with LLL, then the first few basis vectors are what we want.

To keep $e_i$ small enough, we need about $t+r$ messages, where $r$ is the kernel rank of $A$. The larger the $r$ is, the smaller $e_i$ will be.

In my reference solution, I pick $t=512, r=40$, and it took less than 1 hour using a single-threaded sage script to precompute all these.

See [do_precompute.sage](./solve/do_precompute.sage) for more details.

> The idea of this comes from Index Calculus, but after some searching about this I found it is actually pretty similar to [*A chosen text attack on the RSA cryptosystem and some discrete logarithm schemes*](https://link.springer.com/content/pdf/10.1007/3-540-39799-X_40.pdf) (as expected of course).

### Signature forgery

One of the way to do signature forgery is to find a command `./give me flag please # ...` that can be fully factored by $p_j$, so we can forge a signature for it by solving a linear system. But since the message is long, it is not easy to find such command.

> If you insist in using this, you can try to use the trick from [BabyFirst Revenge v2](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2017/babyfirst-revenge-v2/index.php), but this would need a writable directory and it would be a web/misc challenge instead :P

The intended way is to use that fact that a signature pair $(m, s)$ isn't just valid for that single $m$, but also $m+kn$ for every integer $k$. So we need to find a command `./give me flag please # ...` $m'$ such that $m' \equiv m \pmod{n}$.

There is a restriction that `...` must be a valid UTF-8 string. If you remeber [SEETF 2023 - 🤪onelinecrypto](https://demo.hedgedoc.org/s/DnzmwnCd7), you know this can be done by using lattice reduction.

In practice, LLL appear to be not enough for this, but BKZ can do the job. See [solve.sage](./solve/solve.sage) for more details.

# Tan

* Category: Crypto
* Score: 418/500
* Solves: 32

## Description

`tan(x)` is a broken hash function in terms of collision resistance and second preimage resistance. But you surely can't find the preimage of `tan(flag)`, right?

## Solution

Let the flag be $m$ and the output be $t$, then $\arctan(t)+k\pi \approx m$ with some precision loss. Note that $m$ is an integer, so we can use LLL to minimize the decimal part of $\arctan(t)+k\pi$ then $m$ will magically appear.

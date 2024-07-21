# coast

* Category: Crypto
* Score: 465/500
* Solves: 21

## Description

Isogeny cryptography seems so fun, so I build a new cryptosystem based on CSIDH.

## Solution

First, due to how the group action is implemented the sign of `es` in private key does not matter. Second, the order of the auxiliary point `G` leaks the degree of isogeny. (i.e.g `G` has order `p+1` but becomes `(p+1)//3` after a 3-isogeny)

So computing the order of `G` in public key reveals the secret isogeny, and we can compute the shared secret to decrypt the flag. See [solve.sage](./solve.sage) for details.

# Web3

* Round: 29 (2022/12)
* Category: Crypto
* Points: 150
* Solves: 2

## Description

Is this a cryptocurrency or a cryptography challenge? Yes.

Please try to find the private key of an Ethereum account `0x891cf17281bF2a57b25620b144A4E71B395603D4`, and the private key is in the format of `b"ictf{??????}".rjust(32, b"\x00").hex()`. This account has made some transactions on Sepolia Testnet, btw.

> You don't need a lot of computational resources for this challenge. Intended solution works in less than 10 mins, single threaded.

## Solution

First, you can view this account on Etherscan, then recover the public key from the from that transaction (ECDSA signature). Now we have the public key and the known bits of private key, use Meet-In-The-Middle attack (or BSGS) to solve ECDLP to find the private key (flag).

[solve.py](./solve.py) and [solve2.py](./solve2.py) only differs in the way to recover the public key from the transaction, and the BSGS part is both manually implemented with fastecdsa. They both take about 5 mins on my PC.

You can also use [JeanLucPons/Kangaroo](https://github.com/JeanLucPons/Kangaroo), an optimized Pollard's kangaroo implementation for SECPK1 instead. All you need is to clone and compile, then apply it to:

```
0000000000000000000000000000000000000000696374667b0000000000007d
0000000000000000000000000000000000000000696374667bffffffffffff7d
04d60731bb111e51a4b8311281d2e080379e9d0484b888d6ae5105bcb67692f263dd5182a3b9aa1c795eefda3736eaed96e3bd7a4c6280c3940bfd9baae6941d5e
```

It solves ECDLP in less than 10 secs on my PC.

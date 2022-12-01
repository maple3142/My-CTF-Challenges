# Half FFT

* Round: 28 (2022/11)
* Category: Misc
* Points: 200
* Solves: 4

## Description

Can you invert FFT from half of the outputs?

## Solution

FFT/DFT can be seen as evaluating polynomial at complex roots of unity, with inputs be coefficients. Here, we know that the input in this case is all in 0~256, so for each output value can be get 2 linear equation (Re/Im) with the flag being the roots, which can be solved with LLL.

[solve.py](solve.py)

This challenge can be seen as a slightly harder version of [this](https://github.com/maple3142/My-CTF-Challenges/tree/master/Security%20BSides%20Ahmedabad%20CTF%202022/A%20complex%20number).

## Unintended Solution 1

Note that our signal (flag) is real, and we also gives half of the outputs. So when we consider the real component and imaginary component separately, we have a full rank linear system in reals, which can be solved with Gaussian elimination. Thanks @zeski for pointing this out.

> Imagine using LLL so much that you forgot that Gaussian elimination exists. :P

[solve2.py](solve2.py)

## Unintended Solution 2

For real signal, FFT is symmetric:

$$
X_k = \operatorname{conj}(X_{N-k})
$$

So the only value that we don't know is the first one, which is the sum of the flag, but it is not important. Simply set it to 0 and use IFFT and compute the offset by knowing the first char being `i`, and the flag can be easily recovered.

Thnaks @ym555 for pointing this out too.

[solve3.py](solve3.py)

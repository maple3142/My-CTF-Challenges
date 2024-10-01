# MDLP

* Round: 49 (2024/09)
* Category: Crypto
* Points: 100
* Solves: 8

## Description

A multi-dimensional DLP challenge?!

## Solution

$p=2q+1$ and it is only 256 bits, which means it is easy to solve the DLP with cado-nfs. Solving DLP of all bases and the target $y$ with respect to an unknown base, then we can see that flag is just a small linear combination of $\log(g_i)$ and $\log(y)$, so LLL it and get the flag.

For using cado-nfs, because it implements GNFS, which composed of a large-cost one-time precompuation step and many desecent steps for each DLP target. So you will notice that cado-nfs output shows it generated a **snapshot** file that allows cheap computaion for other DLP targets (descent steps). So you can just compute the first part once (the time needed for this differs but it is usually less than 30 minutes) and use its result to solve the rest of the DLPs. See [solve.py](./solve.py).

Moreover, cado-nfs `target=` option even allows specifying multiple targets at once that you don't even need to manage the snapshot files by yourself. See [solve2.py](./solve2.py).

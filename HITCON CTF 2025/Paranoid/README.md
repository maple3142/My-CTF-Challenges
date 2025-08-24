# Paranoid

* Category: Crypto
* Score: 400/500
* Solves: 4

## Description

You can never be too paranoid!

This is a revenge challenge of Pedantic, so the challenge attachment require the flag of Pedantic to open.

## Overview

This challenge is same as Pedantic, except for the LCG function $f$ is being replaced by a simple increment $g(x) = x + 1$.

## Solution

The solution of Pedantic relies on the existence of $c$ such that $f(c) = c$. The existence of fixed point makes all the challenges equal, meaning that we can generate the commitments $Gr_i$ and freely reorder/duplicate/remove them without affecting the validity of the proof. This gives us a lot of flexibility in making the sum of the hashes $h_i$ equal to any target value. However, in this challenge, the function $g$ has no fixed point, so we cannot use the same trick.

Let the number of rounds be $k$ and fix the initial seed $s$ to some value (e.g. zero) and compute $k$ challenges $c_i$. For each round $i$, we sample $m$ random $z$ and compute $m$ commitments $(Gr)_{i,j}=Gz_{i,j}-Yc_i$ and their hashes $h_{i,j}$. To make the proof valid, we need to find a $h_{i,j}$ from each round $i$ such that their sum is equal to the initial seed $s$.

This problem is a **$k$-list problem** if we view each round as a list of $m$ elements. One of the solution to $k$-list problem is to truncate each list to two elements $(x_{i,0},x_{i,1})$, and denote their difference $d_i=x_{i,1}-x_{i,0}$. Then the problem reduces to finding a subset of $\{d_i\}$ that sums to $s - \sum_i x_{i,0}$. On $\mathbb{F}_2^l$ where $k \geq l$, this can be solved in polynomial time using Gaussian elimination. But in $\mathbb{F}_q$, this becomes a subset-sum problem for some random values, which I can't find a way to solve it using lattice reduction or other techniques.

The intended solution here is to use [Wagner's algorithm](https://www.iacr.org/archive/crypto2002/24420288/24420288.pdf), which is an generalization of meet-is-the-middle attack to $k$-list problem. It works like every other divide-and-conquer algorithm (e.g. merge sort) by recursively merging pairs of lists until only one list is left. The merging is done by finding pairs of elements from two lists that sums to a smaller space, and finally we will end up with a single list of elements. By recursively tracking back how the elements are summed, we can find the solution to the $k$-list problem.

In Wagner's algorithm, it takes $\mathcal{O}(k \cdot 2^{n/(1+\lg k)})$ time and each list needs $\mathcal{O}(2^{n/(1+\lg k)})$ elements to solve a $k$-list problem where $n=\lg q=256$. For convenience, we choose $k=2^{15}$ to make the exponent an integer, and we have time complexity $\mathcal{O}(2^{31})$. Each list need $2^{16}=65536$ elements, assuming that each $\mathbb{F}_q$ number takes 32 bytes to store, it takes around 64GB of space to store all the lists at leaf. For the calculation, we know such attack is likely feasible.

Implementing the full Wagner's algorithm from scratch is still a lot of work. Instead, so I found a [Python implementation](https://github.com/conduition/wagner) which can easily solve 128-bit $q$ in around 10 seconds using pypy3. With the help of LLM, I ported it to Go with parallelism, and make it eagerly offloading the lists to disk to reduce memory usage. With `GOMAXPROCS=32` on a machine with Intel Platinum 8352V CPU, it took around an hour with max 4GB memory usage to find a solution. See [here](./exp/solver/main.go) for the implementation.

Once we found the solution, simply construct the proof using the chosen $(Gr)_i$ and $z_i$ and submit it for the flag, see [solve.py](./exp/solve.py).

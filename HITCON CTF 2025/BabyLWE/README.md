# BabyLWE

* Category: Crypto
* Score: 360/500
* Solves: 7

## Description

Simple and straightforward LWE challenge!

## Overview

You are given a standard LWE instance $(A,b)=(A,As+e)$, and each element of the error vector $e$ in randomly sampled from an unknwon set $E=\{e_1,e_2,e_3\}$. The target is to find the secret vector $s$ given only $A$ and $b$.

## Solution

Suppose we know the error set $E$, how would we approach this problem? We would try to find $u,v \in \mathbb{F}_p$ such that $e_i'=ue_i+v$ is sufficiently small, which can be done in many ways (e.g. LLL). When we found such translation $(u,v)$, the LWE instance $(A,b)$ can be rewritten as:

$$
ub+v \cdot \mathbf{1} = uAs + (ue+v \cdot \mathbf{1}) = A(us) + e'
$$

> $\mathbf{1}$ is the all-one vector.

So we got a new LWE instance $(A,ub+v \cdot \mathbf{1})$ with a smaller error vector $e'$, which can be solved more easily by lattice reduction. But in this challenge, we don't know the error set $E$ so we can't find the $(u,v)$ directly isn't it?

Actually, if we rearrange the equation above to:

$$
ub+v \cdot \mathbf{1} - A(us) = e'
$$

Now, it is obvious that the translated short vector $e' \in \mathop{\text{span}}(\mathop{\text{col}}(A),b,\mathbf{1})$. This means we can try to find $e'$ in the short vectors of that subspace, and it does not depend on $(u,v)$ or $E$ at all!

To identify the correct $e'$, just look for a short vector with only 3 distinct elements, and $(u,v)$ can be recovered by solving a linear system. Finally, we can compute $e=u^{-1}(e'-v)$ and solve another linear system $As=b-e$ to get $s$.

To actually find the $e'$, I used BKZ-20 to find it. See my solver [solve.py](./exp/solve.py) for details.

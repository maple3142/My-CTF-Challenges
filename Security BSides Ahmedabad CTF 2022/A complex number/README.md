# A complex number

* Category: Crypto
* Solves: 0/52

## Description

A random complex number probably won't tell you anything about the key right?

## Solution

It is similar to the example given in the **Applications** in [Lenstra–Lenstra–Lovász lattice basis reduction algorithm](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm#Applications) on Wikipedia.

The example only show how to solve it when $r$ is a real number, but it is easy to extend it to complex numbers by taking the real part and imaginary part seperately. Construct the basis and the first row will be the AES key.

Solver: [solve.sage](./solve.sage)

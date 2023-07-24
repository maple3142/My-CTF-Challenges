# typechecker

* Category: Reversing
* Score: 482/500
* Solves: 15

## Description

All you need is to make it compile without error!

## Solution

A lot of the types are defined using tail recursion, and it is easy to see it defines things like how strings are encoded into integers, arithmetic in `GF(67)` and matrix multiplication. In a nutshell, there are two constant 8x8 matrices `A` and `B` and the flag is converted into a 8x8 matrix `X`. The flag has length 62, so the missing part will be converted to `undefined`, which is same as `0`. To pass the check, `X` must satisfy `A*X=X*B (mod 67)`.

By flattening the `A*X-X*B=0 (mod 67)` equations you will get a linear system of `64` unknowns and `64` equations, so gaussian elimination will solve the problem. The system is actually linear (not affine), so the solution will be in a kernel of a matrix. But if you investigate furture you will find the rank of the system is `8*8-8=60`, so the kernel dimension is `8`, this means there are a lot of valid `X` that satisfty `A*X=X*B`. Combining this with the flag format and the fact that flag has length 62, you can eliminate 8 unknowns and get the only possible solution, which is the flag.

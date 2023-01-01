# Generic Flag Checker

* Round: 29 (2022/12)
* Category: Reverse
* Points: 100
* Solves: 8

## Description

I am really bad at naming challenges, sorry :(

## Solution

The main function reads 4 bytes at a time then try to dereference it directly, but the expected segfault somehow doesn't work at all. If you use `strace` then it is easy to see there is some suspicious signals happening.

There is also an extra function in `.init_array`, but IDA will decompile it as JUMPOUT. Read the assembly to see there is a simple push + ret obfuscation, so you can fill it with nop fix the function addresses to make IDA decompiler work again.

That init function simply register a `SIGSEGV` signal handler, but the handler function is broken in decompiler too, so you need to fix another push + ret obfuscation again. It is basically xoring segfaulted address `si->si_addr` (flag input) with a global array, and the success condition is the global array being all zeros. Simply extract that array and using the flag prefix `ictf` to reverse those xor to get the flag.

# Read

* Round: 26 (2022/09)
* Category: Pwn
* Points: 125
* Solves: 6

## Description

Yet another shellcoding challenge, only `read(2)` is allowed this time.

## Solution

First step is to read additional shellcode to bypass 0x20 length limit. And the second step is about finding the address of the flag.

While the mmapped page is randomly generated, it only have 256 possibilities due to the masking operation. So it is pratical to bruteforce. As for checking, you can use `read(2)` syscall trying to read something to it because kernel will return `EFAULT` if the address is invalid.

After getting the address of the flag, we need something to leak the flag as we aren't allowed to `write`. A very simple primitive is by determining segfault or infinite loop to know whether a condition is true. And using a binary search for each flag char is probably the most efficient way to get the flag.

# xkcd 835

* Round: 29 (2022/12)
* Category: Pwn
* Points: 200
* Solves: 7

## Description

I know it is a bit late for a Christmas-themed challenge, but it is still better late than never.

Note: High point value is due to end-of-round, and may not necessarily be indicative of challenge difficulty.

## Solution

There is an UAF if you choose to exit, so you can leak heap address and get another address pointing to `sh` string. Overwrite the heap struct with `nodes[1]="sh"` and partial overwrite `cmp` to `system@plt` then `heap_pop()` to get shell.

Please refer to [solve.py](./solve.py) for more details.

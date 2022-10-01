# Here's some Rev v2

* Round: 26 (2022/09)
* Category: Reverse
* Points: 75
* Solves: 17

## Description

Just another lazy reverse challenge because there is no other challenge today.

## Solution

Decompile with decompyle3 and notice that each byte of the output online depends only on the flag prefix (`flag[:i]`), so bruteforce it byte by byte to recover the flag.

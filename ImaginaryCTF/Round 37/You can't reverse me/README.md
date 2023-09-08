# You can't reverse me

* Round: 37 (2023/08)
* Category: Misc/Reverse
* Points: 100
* Solves: 9

## Description

There are too many great reverse players who can always get my flag from a flag checker, but nothing can be done if you can't even read the binary?

> Only a nc connection and `Dockerfile` is provided to the players.

## Solution

You can use `LD_PRELOAD` to inject code into the process and dump the binary. Although the file format isn't quite correct, tools like IDA can still decompile it easily. Then you will know the checker is just a simple seed-then-xor-with-rand flag checker. Note that the server uses alpine, so you need to use a musl libc implementation for that.

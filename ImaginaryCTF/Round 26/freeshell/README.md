# Free Shell

* Round: 26 (2022/09)
* Category: Misc
* Points: 100
* Solves: 7

## Description

Here's your free shell, can you read the flag?

> Source code aren't provided to players at start, so they need to find their own way to read the source.

## Solution

It is easy to see that only shell builtins works. `echo *` can be used to list files, and `echo "$(<shell.c)"` leaks the source code. After reading the source code, it is obvious that we need to find some way to use `execveat` syscall to execute `/readflag`. This can be done by compiling and loading a custom loadable bash builtins using `enable -f`.

The reason that this challenge exists is because I once solved a pwn challenge that the author forgot to block `execveat`, so I can still execute `/bin/sh`, but wondering if it is possible to execute something else within the shell.

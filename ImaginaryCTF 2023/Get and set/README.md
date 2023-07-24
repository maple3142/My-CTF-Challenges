# Get and set

* Category: Misc
* Score: 500/500
* Solves: 2

## Description

A Pyjail with direct code execution gives you too much freedom, so I made a Pyjail where you can only only `get` and `set`.

## Solution

Get `__builtins__` from `__reduce_ex__(3)[0].__builtins__`, and you can call arbitrary functions using magic methods like `__getattr__` or `__getitem__`.

```sh
(cat payload.txt; cat) | nc get-and-set.chal.imaginaryctf.org 1337
```

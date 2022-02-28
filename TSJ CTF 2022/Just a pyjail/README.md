# Just a pyjail

* Category: Misc (Pyjail)
* Score: 500/500
* Solves: 1/428

## Description

Pyjail is so fun, isn’t it?

Server runs CPython 3.10.2

## Overview

A pyjail challenge. The input can only contains ASCII characters, and `__` (double underscores) are banned. The input are executed with `{'__builtins__': None}`.

Aside from this, it also employs [PEP 578 -- Python Runtime Audit Hooks](https://www.python.org/dev/peps/pep-0578/) to filter some dangerous things too.

## Solution

The first step of solving this needs to be able to get builtin objects, but without any `__`. I used generator frame to access the frame of `__main__`:

```python
def f():
    yield g.gi_frame.f_back.f_back


g = f()
frame = [x for x in g][0]
a = "_" * 2 + "builtins" + "_" * 2
b = frame.f_back.f_globals[a]
```

> You can use async functions too

Now you got every builtin objects, but you still can't simply `import os; os.system('sh')` to get shell. Actually, the remaining part is the real challenge.

If you are familiar with python, you probably know there is a `__loader__` on `__builtins__`, which allows you to import any builtin modules (`sys.builtin_module_names`). And magically, it doesn't trigger the `import` audit event in this version.

The next step is to determine which builtin module can be used to escape the jail. It is easy to find that there were another challenge about audit hooks: [hxp CTF 2020 - audited](https://ctftime.org/task/14380), and one of the [writeup](https://github.com/fab1ano/hxp-ctf-20/tree/main/audited) uses `gc` to get object references. Unfortunately, `gc` is blocked by the hook too.

Trying to Google even harder might give you this interesting writeup: [35c3ctf: Collection - an Unintended Solution!](https://www.da.vidbuchanan.co.uk/blog/35c3ctf-collection-writeup.html). It abuses `LOAD_CONST` instruction's out of bound access to construct a buffer to get **arbitrary memory read/write**.

But constructing code object will trigger `code.__new__` event, which is blocked by the `__new__` in the hook too. It is important to know that the `marshal` builtin module can serialize/deserialize code object too. And it doesn't trigger `code.__new__` event in newer python according to [this](https://bugs.python.org/issue41180#msg396757).

After you get arbitrary memory read/write, it is pretty easy to escape the jail now. An easy way is to abuse the string interning feature (same strings share same memory address), by overwriting strings' internal data, and thus bypass the checks in the hook function.

See [./sol](./sol) for my exploit. `payload.py` is the actual exploit, and `solve.py` is used to send payload to the server.

One of the team that solved this challenge overwrites `os._exit` with `abs` function instead:

```python
dest = id(os._exit)
src = id(abs)

# `res` is the arbitrary read/write buffer
for i in range(0, 0x8 * 12):
    res[dest + i] = res[src + i]
```

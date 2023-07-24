# Wasteful

* Category: Crypto
* Score: 423/500
* Solves: 31

## Description

I am going to make RSA encryption more time-consuming for no reason :P

## Solution

Denote `e_fast` as $e' \approx 2^{1024}$, then `e_slow` $e=e'+t(p-1)(q-1)$ where $t$ is a $2048/3 \approx 682$ bits prime. First we can notice that $(p-1)(q-1) \approx n$, so we can get $t$ by computing $\operatorname{nextPrime}(e/n)$.

Since $t-e \equiv t(p+q)-e' \pmod{n}$, we can get an approximation of $p+q$ by $(t-e\mod{n})/t$. Using $(p+q)^2-4n=(p-q)^2$ we can get an approximation of $p-q$ and thus $p,q$. Note that the error is approximately $\log_2(e'/t) \approx 342$ bits, which is less than the half of $p$ or $q$. This means we can find $p$ or $q$ using coppersmith method and decrypt the flag.

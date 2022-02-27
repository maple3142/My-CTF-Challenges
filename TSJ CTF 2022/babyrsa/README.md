# babyRSA

* Category: Crypto

## Description

![is this rsa?](meme.png)

## Overview

We have $n=pq$, where $p$ is 1024 bit prime and $q$ is 512 bit prime. Define an elliptic curve $E: y^2=x^3+px+q$ over $\mathbb{Z}_n$, flag (with some random padding) are encoded as x coordinate of a point $P$ on curve. The ciphertext is another point $C=eP$, where $e=65537$.

## Solution

By substituting the coorinates of $C$ back to the original curve, we have $ap+q \equiv r \pmod{n}$, where $a, r$ are known. If we change this equation to $\bmod{p}$, we get $q \equiv r \pmod{p}$.

Define another polynomial $f(x)=r-x$, it is easy to see $f(q)=0 \pmod{p}$. Since $q$ is small compared to $n$, we use Coppersmith's method to solve for the root $q$ and factor $n$.

> For more details: [Extensions of Coppersmith algorithm](https://cryptohack.gitbook.io/cryptobook/lattices/applications/extensions-of-coppersmith-algorithm)

Once you got $p,q$, the remaining part should be easy. Change the curve to $\mathbb{F}_p$ and $\mathbb{F}_q$ and compute the order separately, and invert the scalar multiplication to get the flag.

```python
from Crypto.Util.number import *

proof.arithmetic(False)

n = 1084688440161525456565761297723021343753253859795834242323030221791996428064155741632924019882056914573754134213933081812831553364457966850480783858044755351020146309359045120079375683828540222710035876926280456195986410270835982861232693029200103036191096111928833090012465092747472907628385292492824489792241681880212163064150211815610372913101079146216940331740232522884290993565482822803814551730856710106385508489039042473394392081462669609250933566332939789
xx, yy = (
    1079311510414830031139310538989364057627185699077021276018232243092942690870213059161389825534830969580365943449482350229248945906866520819967957236255440270989833744079711900768144840591483525815244585394421988274792758875782239418100536145352175259508289748680619234207733291893262219468921233103016818320457126934347062355978211746913204921678806713434052571635091703300179193823668800062505275903102987517403501907477305095029634601150501028521316347448735695,
    950119069222078086234887613499964523979451201727533569872219684563725731563439980545934017421736344519710579407356386725248959120187745206708940002584577645674737496282710258024067317510208074379116954056479277393224317887065763453906737739693144134777069382325155341867799398498938089764441925428778931400322389280512595265528512337796182736811112959040864126090875929813217718688941914085732678521954674134000433727451972397192521253852342394169735042490836886,
)

e = 65537

r = ZZ((yy ^ 2 - xx ^ 3) % n)
P = PolynomialRing(Zmod(n), "q")
q = P.gen()
f = r - q
q = ZZ(f.monic().small_roots(X=2 ^ 512, epsilon=0.8, beta=0.66)[0])
p = n // q
assert p * q == n

print((log(p) / log(n)).n())

E = EllipticCurve(Zmod(n), [p, q])

phi = E.change_ring(GF(p)).order() * E.change_ring(GF(q)).order()
d = inverse_mod(e, phi)
x, y = (d * E(xx, yy)).xy()
print(long_to_bytes(x))
```

Another way to factor it by @Kuruwa: 

Since $r \equiv q \pmod{p} \implies r=q+xp$, the vector $v=(q^2,2^{512}q)$ will be in lattice spanned by the following basis $B$.

$$
B=
\begin{bmatrix}
q+xp & 2^{512} \\
n & 0
\end{bmatrix}
$$

Since $q$ is just 512 bits, $v$ is probably a short vector in it. Run LLL or Lagrange-Gauss algorithm could produce the vector $v$.

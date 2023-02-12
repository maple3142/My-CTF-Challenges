from Crypto.Util.number import *

exec(open("output.txt").read())

# e*magic=e*(d+p+q)=1+e*p+e*q (mod phi)
# e*magic-1=e*(p+q) (mod phi)
# e*magic-1=e*(p+q+phi) (mod phi)
# p+q+phi=p+q+(p-1)*(q-1)=p+q+n-p-q+1=n+1
# e*magic-1-e*(n+1)=0 (mod phi)

kphi = (e * magic - 1) - e * (1 + n)
d = pow(e, -1, kphi)
m = pow(c, d, n)
print(long_to_bytes(m))

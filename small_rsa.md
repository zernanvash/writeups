# SMALL RSA
``` python
from Crypto.Util.number import getPrime 
flag="FLAG*****************************" 
c="" p=getPrime(12) 
q=getPrime(12) 
N=p*q E=65537 
for l in flag: 
  c+=format(pow(ord(l),E,N), '08X') print(c)
```

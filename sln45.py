import random
from hashlib import sha1
from sln11 import key_gen
from sln33 import modexp
     
class DSA:
    
    def __init__(self,p,q,g):
        self.g,self.p,self.q = g,p,q
        self.x = random.randint(1,q-1)
        self.y = modexp(g,self.x,p)

    def sign(self,m):
        k = random.randint(1,self.q-1)
        r = modexp(self.g,k,self.p)%self.q
        h = int(sha1(m).hexdigest(),16)%self.q
        s = (h+self.x*r)*pow(k,-1,self.q)%self.q
        self.k = k
        return r,s
    
    def verify(self,r,s,m):
        if r >= self.q or s >= self.q: return False
        w = pow(s,-1,self.q)
        h = int(sha1(m).hexdigest(),16)%self.q
        u1,u2 = (h*w)%self.q,(r*w)%self.q
        v = (modexp(self.g,u1,self.p)*modexp(self.y,u2,self.p))%self.p%self.q
        return v == r
        
if __name__ == '__main__':
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    
    print('===== g = 0 =====')
    dsa = DSA(p,q,0)
    m = b'hello world'
    r,s = dsa.sign(m)
    print('genuine signature: r = %s; s = %s'%(r,s))
    print('r = 0 signature validation: %s'%(dsa.verify(0,int.from_bytes(key_gen(),'big'),b'goodbye world')))
    
    print('\n===== g = 1 =====')
    dsa = DSA(p,q,1)
    z,y = random.randint(1,q-1),dsa.y
    r = modexp(y,z,p)%q
    s = r*pow(z,-1,q)%q
    print('magic signature validation: %s'%(dsa.verify(r,s,b'goodbye world')))
    
    
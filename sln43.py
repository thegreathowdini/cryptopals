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
        r = s = 0
        while r*s == 0:
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
 
def x_from_k(k,s,r,q,h): return (s*k-int(h,16))*pow(r,-1,q)%q

        
if __name__ == '__main__':
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

    print('===== DSA VERIFICATION =====')
    dsa = DSA(p,q,g)
    m = key_gen()
    r,s = dsa.sign(m)
    print('true signature verification: %s'%dsa.verify(r,s,m))
    print('false signature verification: %s'%dsa.verify(r,s,key_gen()))

    print('\n===== KEY FROM NONCE VERIFICATION =====')
    print('computed key: %s'%x_from_k(dsa.k,s,r,q,sha1(m).hexdigest()))
    print('true key: %s'%dsa.x)

    print('\n===== CRACK KEY =====')
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    h = 'd2d0714f014a9784047eaeccf956520045c45265'
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    
    for k in range(2**16):
        x = x_from_k(k,s,r,q,h)
        if sha1(hex(x)[2:].encode()).hexdigest() == '0954edd5e0afe5542a4adf012611a91912a3ec16': 
            print('key recovered: %s'%x)
            break
    else: print('failed')
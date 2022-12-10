import random,re
from sln11 import key_gen
from sln39 import RSA,int_to_bytes,bytes_to_int
from sln33 import modexp

class RSA_padding(RSA):
    def pad(self,m,l): return b'\x00\x02' + key_gen(l-3-len(m)) + b'\x00' + m
    
    def pad_check(self,c):
        p = b'\x00'+int_to_bytes(modexp(c,self.d,self.n))
        return p[:2] == b'\x00\x02' and len(p)==self.key_length//4

def pkcs1_unpad(b): return re.findall(b'\x00\x02.{7,}\x00(.*)',b)[0]

def union(M,low,high):
    to_remove = set()
    for (a,b) in M:
        if a <= high and b >= low: 
            low,high = min(low,a),max(high, b)
            to_remove.add((a,b))
    for pair in to_remove: M.remove(pair)
    M.append((low, high))
   
def bleichenbacher(l,m):
    rsa = RSA_padding(3,l//2)
    m = rsa.pad(m,l//8)
    c = bytes_to_int(rsa.encrypt(m))
    
    B,i,s = 2**(l-16),1,1
    e,n = rsa.public_key()
    M = [(2*B,3*B-1)]
    
    while not rsa.pad_check((c*modexp(s,e,n))%n): s += 1
        
    while not (len(M) == 1 and M[0][0] == M[0][1]):        
        if i == 1:
            s = n//(3*B)
            while not rsa.pad_check((c*modexp(s,e,n))%n): 
                s += 1
                if not (s-n//(3*B))%10000: print('initialisation for s: tried %s values'%(s-n//(3*B)))
            print('s initialised')

        elif len(M) > 1:
            s += 1
            while not rsa.pad_check((c*modexp(s,e,n))%n): s += 1

        elif len(M) == 1:
            a,b = M[0]
            r = 2*(b*s-2*B)//n
            s = (2*B+r*n)//b

            while not rsa.pad_check((c*modexp(s,e,n))%n): 
                s += 1
                if s > (3*B+r*n)//a:
                    r += 1
                    s = (2*B+r*n)//b

        M_next = []
        for (a,b) in M:
            r_min,r_max = (a*s-3*B+n)//n,(b*s-2*B)//n
            for r in range(r_min,r_max+1):
                low = max(a,(2*B+r*n-1)//s+1)
                high = min(b,(3*B-1+r*n)//s)
                union(M_next,low,high)
        M = M_next
        i += 1
        if not i%1000: print('updated %s rounds, M0-distance %s'%(i,M[0][1]-M[0][0]))
    
    print('M converged')
    return pkcs1_unpad(b'\x00'+int_to_bytes(M[0][0]))
    
    
if __name__ == '__main__':
    l = 256
    m = b'kick it, CC'
    print('plaintext: %s'%bleichenbacher(l,m))
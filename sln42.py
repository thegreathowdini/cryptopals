import hashlib,re
from sln33 import modexp
from sln39 import RSA,int_to_bytes,bytes_to_int
from sln40 import cbrt

class DSA(RSA):

    def sign(self,m): 
        h = hashlib.sha256(m).digest()
        h = b'\x00\x01' + b'\xff'*(self.key_length//8-len(h)-8) + b'\x00ASN.1' + h
        return int_to_bytes(modexp(bytes_to_int(h),self.d,self.n))
        
    def verify(self,m,s): 
        h = b'\x00'+int_to_bytes(modexp(bytes_to_int(s),self.e,self.n))
        r = re.match(b'\x00\x01\xff*\x00ASN.1(.{32}).*',h)
        if not r: return False
        return r[1] == hashlib.sha256(m).digest()

def forger(m,kl):
    h = hashlib.sha256(m).digest()
    l = 0
    s = b'\x00\x01'+b'\xff'*l+b'\x00ASN.1'+h
    while bytes_to_int(s) < d.n:
        while bytes_to_int(s) < d.n:
            c = cbrt(bytes_to_int(s))
            t = b'\x00'+int_to_bytes(c*c*c)
            r = re.match(b'\x00\x01\xff*\x00ASN.1(.{32}).*',t)
            if r and r[1] == h: return int_to_bytes(c)
            s += b'\x00'
        l += 1
        s = b'\x00\x01'+b'\xff'*l+b'\x00ASN.1'+h
    return None
    
        
if __name__ == '__main__':
    d = DSA(3,1024)
    m = b'hi mom'
    print('message: %s'%m)
    s = forger(m,d.key_length//8)
    if s: 
        print('forged signature: %s'%s)
        print('verification: %s'%d.verify(m,s))
    

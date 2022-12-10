import base64,decimal
from sln33 import modexp
from sln39 import RSA,int_to_bytes,bytes_to_int

class oracle(RSA):
    def is_odd(self,c): return modexp(c,self.d,self.n)%2
        
        
if __name__ == '__main__':
    rsa = oracle(3,512)
    c = bytes_to_int(rsa.encrypt(base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')))
    l,u,f,k = decimal.Decimal(0),decimal.Decimal(rsa.n),modexp(2,rsa.e,rsa.n),b''    
    decimal.getcontext().prec = 512
        
    for _ in range(1024):
        c = c*f%rsa.n
        if rsa.is_odd(c): l = (l+u)/2
        else: u = (l+u)/2
        if int(l) and int_to_bytes(int(u)) != k: 
            k = int_to_bytes(int(u))
            print(k)
    
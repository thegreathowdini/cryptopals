import math
from sln11 import key_gen
from sln33 import modexp
from Crypto.Util.number import getPrime        

def bytes_to_int(b): return int.from_bytes(b,'big')

def int_to_bytes(i): 
    p = hex(i)[2:]
    if len(p)%2: p = '0'+p
    return b''.join([bytes([int(p[i*2:(i+1)*2],16)]) for i in range(len(p)//2)])
        
class RSA:    
    def __init__(self,e,key_length):
        self.e,self.key_length,et = e,key_length,0
        while not et%e:
            p,q = getPrime(key_length),getPrime(key_length)
            et = (p-1)*(q-1)
        self.n,self.d = p*q,pow(e,-1,et)
        
    def public_key(self): return self.e,self.n
    def encrypt(self,p): return int_to_bytes(modexp(bytes_to_int(p),self.e,self.n))
    def decrypt(self,c): return int_to_bytes(modexp(bytes_to_int(c),self.d,self.n))
    
if __name__ == '__main__':
    rsa = RSA(3,1024)
    p = key_gen()
    print('plaintext: %s'%p)
    c = rsa.encrypt(p)
    print("ciphertext: %s"%c)
    print("decrypted: %s"%rsa.decrypt(c))
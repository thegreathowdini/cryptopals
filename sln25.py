import base64
from sln10 import xor_bytes
from sln11 import key_gen
from sln18 import aes_ctr
    
def edit(c,k,o,n,nonce=0):
    p = aes_ctr(k,c,nonce)
    if o+len(n) > len(p): return None
    p = p[:o] + n + p[o+len(n):]
    return aes_ctr(k,p,nonce)
    

if __name__ == '__main__':
    p = base64.b64decode(open('files/25.txt','r').read())
    key = key_gen()
    c = aes_ctr(key,p)
    
    ks = edit(c,key,0,b'\x00'*len(c))
    print('decrypted ciphertext check: %s'%(xor_bytes(ks,c) == p))
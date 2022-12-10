import base64,struct
from sln7 import aes_ecb
from sln10 import xor_bytes

def aes_ctr(key,c,nonce=0):
    p = b''
    ctr = 0
    while c:
        ks = aes_ecb(key,struct.pack('<Q',nonce)+struct.pack('<Q',ctr),decrypt=False,pad=False)
        c,p,ctr = c[min(len(ks),len(c)):], p+xor_bytes(ks,c), ctr+1
    return p
    

if __name__ == '__main__': 
    c = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    key = b'YELLOW SUBMARINE'
    print('plaintext: %s'%aes_ctr(key,c).decode())
    
    
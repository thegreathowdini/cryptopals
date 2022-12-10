import random,base64
from sln9 import pkcs7_unpad
from sln10 import aes_cbc,xor_bytes
from sln11 import key_gen

def padding_oracle(c):
    try: aes_cbc(key,c,iv); return True
    except: return False
    
def one_byte(ct,iv,s,first=False,start=0):
    ending = xor_bytes(s,bytes([len(s)+1])*len(s))
    for i in range(start,256):
        if first and i==iv[-1]: continue
        test_iv = iv[:-len(s)-1] + bytes([i]) + ending
        if padding_oracle(test_iv + ct): return i

def one_block(ct,iv,z,first=False):
    s = b''
    while len(s) < len(ct):
        if not s and first:
            a = one_byte(ct,iv,s,first=True)
            e = a^1^iv[-1]
            s = xor_bytes(bytes([e])*e,iv[-e:])
        else: s = bytes([one_byte(ct,iv,s)^(len(s)+1)]) + s
    return s
        
def po_decrypt(c,b=16):
    k = [c[n*b:(n+1)*b] for n in range(len(c)//b)]
    p = [xor_bytes(one_block(k[-i-1],k[-i-2],i,first=(i==0)),k[-i-2]) for i in range(len(k)-1)]
    return b''.join(p[::-1])
        
if __name__ == '__main__':
    key,iv = key_gen(),key_gen()
    c = open('files/17.txt','r').read().splitlines()[random.randint(0,9)]
    c = aes_cbc(key,base64.b64decode(c),iv,decrypt=False)
    print('ciphertext: %s'%base64.b64encode(c))
    print('plaintext: %s'%pkcs7_unpad(po_decrypt(iv+c)))
        
        

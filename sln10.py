import base64
from sln7 import aes_ecb
from sln9 import pkcs7_pad,pkcs7_unpad

def xor_bytes(a,b): return b''.join(bytes([x^y]) for x,y in zip(a,b))
def aes_cbc(k,m,iv=None,decrypt=True,block_size=16):
    if not iv: iv = b'\x00'*len(k)
    if not decrypt:
        m = pkcs7_pad(m,block_size=len(k))
        chunks = [m[i*block_size:(i+1)*block_size] for i in range(len(m)//block_size)]
        n,c = 0,b''
        while n < len(chunks):
            iv,n = aes_ecb(k,xor_bytes(chunks[n],iv),pad=False,decrypt=False),n+1
            c += iv
        return c
    else:
        chunks = [m[i*block_size:(i+1)*block_size] for i in range(len(m)//block_size)]
        return pkcs7_unpad(b''.join(xor_bytes(x,aes_ecb(k,y,pad=False)) for x,y in zip([iv]+chunks[:-1],chunks)))

if __name__ == '__main__':
    c = base64.b64decode(open('files/10.txt','r').read())
    key = b'YELLOW SUBMARINE'
    print(aes_cbc(key,c).decode())
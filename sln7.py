from Crypto.Cipher import AES
from sln9 import pkcs7_pad,pkcs7_unpad
import base64

def aes_ecb(k,m,decrypt=True,pad=True):
    a = AES.new(k, AES.MODE_ECB)
    return (pkcs7_unpad(a.decrypt(m)) if pad else a.decrypt(m)) if decrypt else a.encrypt(pkcs7_pad(m) if pad else m)
    
if __name__ == '__main__':
    c = base64.b64decode(open('files/7.txt','r').read())
    key = b'YELLOW SUBMARINE'
    p = aes_ecb(key,c)
    print(p.decode())
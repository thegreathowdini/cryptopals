import binascii
from sln9 import pkcs7_pad
from sln10 import aes_cbc,xor_bytes

def limited_CBC_MAC(m): return aes_cbc(key,m,decrypt=False)[-len(key):]

key = b'YELLOW SUBMARINE'
p = b"alert('MZA who was that?');\n"
h = aes_cbc(key,p,decrypt=False)[-len(key):]
print('original JS: %s'%p)
print('cbc-mac: %s'%binascii.hexlify(h).decode())

f = b"alert('Ayo, the Wu is back!'); //"
m = limited_CBC_MAC(f)
f = pkcs7_pad(f) + xor_bytes(m,p[:len(key)]) + p[len(key):]
h = aes_cbc(key,f,decrypt=False)[-len(key):]
print('\nmodified JS: %s'%f)
print('cbc-mac: %s'%binascii.hexlify(h).decode())

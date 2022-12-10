import base64
from sln3 import hex_decode
from sln10 import xor_bytes
from sln11 import key_gen
from sln18 import aes_ctr
    
key = key_gen()
true_plaintexts = [base64.b64decode(l) for l in open('files/20.txt','r').read().splitlines()]
ciphertexts = [aes_ctr(key,l,0) for l in true_plaintexts]
l = max(len(t) for t in ciphertexts)

ks = []
for i in range(l):
    c = [t[i] for t in ciphertexts if len(t)>i]
    ks.append(hex_decode(c,hex=False)[1])

for tp,c in zip(true_plaintexts,ciphertexts):
    print('true plaintext: %s'%tp)
    print('guessed plaintext: %s\n'%xor_bytes(c,ks))
    
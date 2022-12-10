import binascii

d = open('files/8.txt','r').read().splitlines()
for i,l in enumerate(d):
    c = binascii.unhexlify(l)
    chunks = [c[i*16:(i+1)*16] for i in range(len(c)//16)]
    if len(chunks)-len(set(chunks)): print('probable ECB ciphertext at line %s'%i)
    

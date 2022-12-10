import random,base64
from sln10 import xor_bytes
from sln11 import key_gen

def fake_rc4(m,k):
    k = key_gen(len(m))
    if random.random() <= .001:
        if len(m) > 15: k = k[:15] + z15 + k[16:]
        if len(m) > 31: k = k[:31] + z31 + k[32:]
    return xor_bytes(m,k)
    
def oracle(p): return fake_rc4(p.encode()+base64.b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F'.encode()),key_gen())


if __name__ == '__main__':
    z15,z31 = key_gen(1),key_gen(1)
    print('TRUE BIASES: z15: %s, z31: %s'%(z15,z31))
    
    d15,d31 = {},{}
    for _ in range(2**17):
        c = fake_rc4(b'\x00'*40,key_gen())
        if c[15] in d15: d15[c[15]] += 1
        else: d15[c[15]] = 1
        if c[31] in d31: d31[c[31]] += 1
        else: d31[c[31]] = 1
    e15,e31 = max(d15,key=lambda x:d15[x]),max(d31,key=lambda x:d31[x])
    print('ESTIMATED BIASES: z15: %s, z31: %s'%(bytes([e15]),bytes([e31])))
    
    pa,pb = b'',b''
    for i in range(16):
        d15,d31 = {},{}
        for _ in range(2**17):
            c = oracle('A'*(15-i))
            if c[15] in d15: d15[c[15]] += 1
            else: d15[c[15]] = 1
            if len(c) > 31:
                if c[31] in d31: d31[c[31]] += 1
                else: d31[c[31]] = 1
        pa += bytes([max(d15,key=lambda x:d15[x])^e15])
        if d31: pb += bytes([max(d31,key=lambda x:d31[x])^e31]) 
        print('cracked so far: %s'%(pa+b'_'*(15-i)+pb+b'_'*(15-i)))
    print('cracked cookie: %s'%(pa+pb))
    
    
            
            
    
    
import struct,binascii
from Crypto.Hash import MD4
from sln11 import key_gen
from sln28 import leftrotate

def my_md4(m,ml=None,h=[0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476]):
    if not ml: ml = len(m) * 8
    m += b'\x80' + b'\x00'*(-(len(m)+9)%64) + struct.pack('<Q', ml)
    
    chunks = [m[i*64:(i+1)*64] for i in range(len(m)//64)]
    for chunk in chunks:
        X,t = list(struct.unpack('<16I', chunk)),h.copy()

        Xi = [3,7,11,19]
        for n in range(16):
            i,j,k,l = map(lambda x:x%4,range(-n,-n+4))
            K,S = n,Xi[n%4]
            hn = t[i] + ((t[j]&t[k])|(~t[j]&t[l])) + X[K]
            t[i] = leftrotate(hn&0xFFFFFFFF,S,32)

        Xi = [3,5,9,13]
        for n in range(16):
            i,j,k,l = map(lambda x:x%4,range(-n,-n+4))
            K,S = n%4*4+n//4,Xi[n%4]
            hn = t[i] + ((t[j]&t[k])|(t[j]&t[l])|(t[k]&t[l])) + X[K] + 0x5A827999
            t[i] = leftrotate(hn&0xFFFFFFFF,S,32)

        Xi = [3,9,11,15]
        Ki = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for n in range(16):
            i,j,k,l = map(lambda x:x%4,range(-n,-n+4))
            K,S = Ki[n],Xi[n%4]
            hn = t[i] + (t[j]^t[k]^t[l]) + X[K] + 0x6ED9EBA1
            t[i] = leftrotate(hn&0xFFFFFFFF,S,32)
            
        h = [((v+n)&0xFFFFFFFF) for v,n in zip(h,t)]
        
    return ''.join(f'{value:02x}' for value in struct.pack('<4L',*h))

def md4_mac(m,k): return my_md4(k+m)

def get_padding(m): return b'\x80' + b'\x00'*((55-len(m))%64) + struct.pack('<Q',len(m)*8)

if __name__ == '__main__':
    key = key_gen()
    
    test_message = key_gen()
    print('message: %s'%test_message)
    h = my_md4(test_message)
    print('md4 hash: %s'%h)
    t = MD4.new()
    t.update(test_message)
    print('checking md4 implementation: %s'%(h==t.hexdigest()))
    print('testing wrong message authentication: %s\n'%(h==my_md4(key_gen()+test_message)))
    
    original_message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    original_hash = md4_mac(original_message,key)
    print('original message: %s'%original_message)
    
    regs = struct.unpack('<4L',binascii.unhexlify(original_hash))
    for k in range(20):
        glue_padding = get_padding(b'A'*k+original_message)
        extended_message = original_message + glue_padding + b';admin=true'
        test_hash = my_md4(b';admin=true',(k+len(extended_message))*8,[regs[0],regs[1],regs[2],regs[3]])
        if test_hash == md4_mac(extended_message,key): 
            print('forged signature for message: %s'%extended_message)
            print('signature: %s'%test_hash)
            break
    else: print('failed to find extension--increase key length range?'); quit()

    
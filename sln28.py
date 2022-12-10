import struct
from hashlib import sha1
from sln11 import key_gen

def leftrotate(v,d,l): return ((v<<d)%(1<<l))|(v>>(l-d))

def my_sha1(m,ml=0,h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0):
    if not ml: ml = len(m)*8
    m += b'\x80' + b'\x00'*((55-len(m))%64) + struct.pack('>Q',ml)
    
    chunks = [m[i*64:(i+1)*64] for i in range(len(m)//64)]
    for chunk in chunks:
        words = [struct.unpack('>I',chunk[i:i+4])[0] for i in range(0,len(chunk),4)]
        for i in range(16,80): words.append(leftrotate(words[i-3]^words[i-8]^words[i-14]^words[i-16],1,32))
        (a,b,c,d,e) = (h0,h1,h2,h3,h4)
        
        for i in range(80):
            if i < 20: f,k = d^(b&(c^d)),0x5A827999
            elif i < 40: f,k = b^c^d,0x6ED9EBA1
            elif i < 60: f,k = (b&c)|(d&(b|c)),0x8F1BBCDC
            else: f,k = b^c^d,0xCA62C1D6

            a,b,c,d,e = leftrotate(a,5,32)+f+e+k+words[i] & 0xffffffff,a,leftrotate(b,30,32),c,d
        
        h0,h1,h2,h3,h4 = (h0+a)&0xffffffff,(h1+b)&0xffffffff,(h2+c)&0xffffffff,(h3+d)&0xffffffff,(h4+e)&0xffffffff
    
    return '%08x%08x%08x%08x%08x'%(h0,h1,h2,h3,h4)
    
def sha1_mac(m,k): return my_sha1(k+m)

if __name__ == '__main__':
    key = key_gen()
    
    test_message = key_gen()
    print('message: %s'%test_message)
    h = my_sha1(test_message)
    print('sha1 hash: %s'%h)
    print('checking sha1 implementation: %s'%(h==sha1(test_message).hexdigest()))
    print('testing wrong message authentication: %s'%(h==my_sha1(key_gen()+test_message)))
    

        
        
        
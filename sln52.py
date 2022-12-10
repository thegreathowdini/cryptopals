from sln7 import aes_ecb
from sln9 import pkcs7_pad
from sln11 import key_gen

def MD(m,h,return_all=False):
    chunks = [m[i*len(h):(i+1)*len(h)] for i in range(len(m)//len(h))]
    i = []
    for chunk in chunks: 
        h = aes_ecb(pkcs7_pad(h),pkcs7_pad(chunk),False)[:len(h)]
        i.append(h)
    return i if return_all else h
    
def int_to_bytes(i,l):
    p = hex(i)[2:]
    p = '0'*(l*2-len(p))+p
    return b''.join([bytes([int(p[i*2:(i+1)*2],16)]) for i in range(len(p)//2)])

def find_col(h):
    d = {}
    for i in range(256**len(h)):
        p = int_to_bytes(i,len(h))
        t = MD(p,h)
        if t in d: return p,d[t],t
        else: d[t] = p
    return print('failed to find collision')

if __name__ == '__main__':
    n,l = 4,3
    h,c = key_gen(l),[b'']
    print('generating 2**%s collisions with initial hash state %s'%(n,h))
    
    z = h
    for i in range(n):
        x,y,z = find_col(z)
        print('stage %s collision found: %s and %s both hash to %s'%(i+1,x,y,z))
        c = [d+x for d in c] + [d+y for d in c]
    print('done. collision hashes: %s'%c)
    print('\nCHECK:')
    for d in c: print('%s hashes from %s to %s'%(d,h,MD(d,h)))
        
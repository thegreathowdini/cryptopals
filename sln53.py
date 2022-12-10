from sln11 import key_gen
from sln52 import MD,int_to_bytes

def find_col(k,h):
    ld,sd = {},{}
    for i in range(256**len(h)):
        p = int_to_bytes(i,len(h))
        st,lt = MD(p,h),MD(p*(2**(k-1)+1),h)
        if lt in sd: return sd[lt],p*(2**(k-1)+1),lt
        elif st in ld: return p,ld[st],st
        else: sd[st],ld[lt] = p,p*(2**(k-1)+1)

def use_blocks(blocks,n):
    d = n-len(blocks)
    return b''.join(blocks[i][(d>>i)&1] for i in range(len(blocks)))

def bridge(z,cache):
    for i in range(256**len(z)):
        p = int_to_bytes(i,len(z))
        t = MD(p,z)
        if t in cache: return p,cache.index(t)
    print('failed to find bridge')
    quit()
    

if __name__ == '__main__':
    k,l = 3,3
    h,M = key_gen(l),key_gen(l*2**k)
    blocks = []
    
    print('generating expandable messages of lengths %s to %s'%(k,k+2**k-1))
    z = h
    for i in range(k):
        s,l,z = find_col(i+1,z)
        print('n = %s collision found: %s and %s both hash to %s'%(i+1,s,l,z))
        blocks.append((s,l))
        
    print('\nCHECK:')
    for i in range(k,k+2**k):
        m = use_blocks(blocks,i)
        print('length %s: %s hashes to %s'%(i,m,MD(m,h)))
        
    print('\nFORGERY:')
    print('original message length: %s'%len(M))
    cache = MD(M,h,True)
    print('original hash: %s'%cache[-1])
    cache = cache[k:k+2**k-1]
    p,i = bridge(z,cache)
    print('found bridge %s to point %s blocks into message'%(p,i+k))
    F = use_blocks(blocks,i+k) + p + M[len(p)*(i+k+1):]
    print('forged message length: %s'%len(F))
    print('forged message hash: %s'%MD(F,h))
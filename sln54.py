from sln11 import key_gen
from sln52 import MD,int_to_bytes

def find_col(s1,s2):
    d1,d2 = {},{}
    for i in range(256**len(s1)):
        p = int_to_bytes(i,len(s1))
        t1,t2 = MD(p,s1),MD(p,s2)
        if t1 in d2: return p,d2[t1],t1
        elif t2 in d1: return d1[t2],p,t2
        else: d1[t1],d2[t2] = p,p
    return print('failed to find collision')
    
    
if __name__ == '__main__':
    k,l = 4,3
    h = key_gen(l)
    rs,d = [],{}
    
    ml = len('result%s'%(2**k))
    ml += -ml%l
    for i in range(2**k):
        m = 'result%s'%i
        m = 'result' + '0'*(ml-len(m)) + str(i)
        rs.append(m)
        d[MD(m.encode(),h)] = b''
    cs = ris = [c for c in d]
    print('initial states: %s'%ris)
    
    for i in range(k):
        ncs = []
        for j in range(len(cs)//2):
            x,y,z = find_col(cs[j*2],cs[j*2+1])
            ncs.append(z)
            for n in range(2**i): 
                d[ris[j*(2**(i+1))+n]] += x
                d[ris[j*(2**(i+1))+2**i+n]] += y
        cs = ncs
        print('stage %s funnelling done. states left: %s'%(i+1,len(cs)))
    print('done. prediction: %s'%cs[0])
    
    print('\nCHECK:')
    for r in rs: 
        m = r.encode() + d[MD(r.encode(),h)]
        print('%s hashes to %s'%(m,MD(m,h)))
    
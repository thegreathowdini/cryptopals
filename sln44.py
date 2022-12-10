from hashlib import sha1
from sln43 import x_from_k
        
if __name__ == '__main__':
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    
    f = [l.split(': ')[1].strip() for l in open('files/44.txt','r').read().splitlines()]
    d = {i:{'msg':f[i*4],'s':f[(i*4)+1],'r':f[(i*4)+2],'m':f[(i*4)+3]} for i in range(len(f)//4)}
    
    for i in d: 
        for j in range(i+1,len(d)):
            if d[i]['r'] == d[j]['r']: break
        else: continue
        break
    
    m1,m2,s1,s2 = int(d[i]['m'],16),int(d[j]['m'],16),int(d[i]['s']),int(d[j]['s'])
    k = ((m1-m2)*pow(s1-s2,-1,q))%q
    print('repeated key: %s'%k)
    
    x = x_from_k(k,s1,int(d[i]['r']),q,d[i]['m'])
    print('private key: %s'%x)
    print('verification: %s'%(sha1(hex(x)[2:].encode()).hexdigest() == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'))
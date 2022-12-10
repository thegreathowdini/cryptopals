from sln11 import key_gen
from sln39 import RSA,int_to_bytes,bytes_to_int

def cbrt(n):
    l = 10**((len(str(n))-1)//3)
    u = 10*l
    while u > l+1: 
        m = (u+l)//2
        t = m*m*m
        if t == n: return m
        elif t > n: u = m
        else: l = m
    return u

if __name__ == '__main__':
    p,c = key_gen(),[]
    print('true plaintext: %s'%p)
    
    for _ in range(3):
        r = RSA(3,1024)
        c.append((r.public_key()[1],r.encrypt(p)))
    
    cube = pow(c[1][0]*c[2][0],-1,c[0][0])*c[1][0]*c[2][0]*bytes_to_int(c[0][1])
    cube += pow(c[0][0]*c[2][0],-1,c[1][0])*c[0][0]*c[2][0]*bytes_to_int(c[1][1])
    cube += pow(c[1][0]*c[0][0],-1,c[2][0])*c[1][0]*c[0][0]*bytes_to_int(c[2][1])
    cube %= c[0][0]*c[1][0]*c[2][0]
    cube = cbrt(cube)
    print('solved plaintext: %s'%int_to_bytes(cube))
    
    
    
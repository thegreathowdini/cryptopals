import random

def modexp(b,e,m):
    x = 1
    while e > 0: b,e,x = b*b%m, e//2, b*x%m if e%2 else x
    return x
    
    
if __name__ == '__main__':
    print('===== SIMPLE DIFFIE-HELLMAN =====')
    p,g = 37,5
    print('PARAMS\np = %s\n\ng = %s\n'%(p,g))
    a,b = random.randint(1,p),random.randint(1,p)
    print('PRIVATE KEYS\na = %s\n\nb = %s\n'%(a,b))
    A,B = modexp(g,a,p),modexp(g,b,p)
    print('PUBLIC KEYS\nA = %s\n\nB = %s\n'%(A,B))
    print('SESSION KEYS')
    Sa,Sb = modexp(B,a,p),modexp(A,b,p)
    print('alice\'s session key: %s\n'%Sa)
    print('bob\'s session key: %s\n'%Sb)
    print('coordination check: %s\n\n'%(Sa==Sb))
    
    print('===== REALISTIC DIFFIE-HELLMAN =====')
    p,g = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff,2
    print('PARAMS\np = %s\n\ng = %s\n'%(p,g))
    a,b = random.randint(1,p),random.randint(1,p)
    print('PRIVATE KEYS\na = %s\n\nb = %s\n'%(a,b))
    A,B = modexp(g,a,p),modexp(g,b,p)
    print('PUBLIC KEYS\nA = %s\n\nB = %s\n'%(A,B))
    print('SESSION KEYS')
    Sa,Sb = modexp(B,a,p),modexp(A,b,p)
    print('alice\'s session key: %s\n'%Sa)
    print('bob\'s session key: %s\n'%Sb)
    print('coordination check: %s\n\n'%(Sa==Sb))
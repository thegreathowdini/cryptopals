import random, hashlib
from sln10 import aes_cbc
from sln11 import key_gen
from sln33 import modexp
   
def aes_key_from_session(s): return hashlib.sha1(hex(s).encode()).digest()[:16]

if __name__ == '__main__':
    print('===== STANDARD DIFFIE-HELLMAN =====')
    p,g = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff,2
    a,b = random.randint(1,p),random.randint(1,p)
    A,B = modexp(g,a,p),modexp(g,b,p)
    Sa,Sb = modexp(B,a,p),modexp(A,b,p)
    Sa,Sb = aes_key_from_session(Sa),aes_key_from_session(Sb)
    msg = key_gen()
    print('PARAMETERS')
    print('message: %s'%msg)
    print('alice\'s aes key: %s'%Sa)
    print('bob\'s aes key: %s'%Sb)
    print('coordination check: %s\n'%(Sa==Sb))
    
    iva,ivb = key_gen(),key_gen()
    c = aes_cbc(Sa,msg,iva,decrypt=False)
    print('ALICE SEND')
    print('ciphertext: %s'%c)
    print('iv: %s'%iva)
    d = aes_cbc(Sb,c,iva)
    print('bob decrypts: %s'%d)
    print('transmission check: %s\n'%(d==msg))
    
    c = aes_cbc(Sb,msg,ivb,decrypt=False)
    print('BOB SEND')
    print('ciphertext: %s'%c)
    print('iv: %s'%ivb)
    d = aes_cbc(Sa,c,ivb)
    print('alice decrypts: %s'%d)
    print('transmission check: %s\n'%(d==msg))
    
    print('===== MITM KEY-FIXING ATTACK =====')
    Sa,Sb = modexp(p,a,p),modexp(p,b,p)
    Sa,Sb,Sm = aes_key_from_session(Sa),aes_key_from_session(Sb),aes_key_from_session(0)
    msg = key_gen()
    print('PARAMETERS')
    print('message: %s'%msg)
    print('alice\'s aes key: %s'%Sa)
    print('bob\'s aes key: %s'%Sb)
    print('mitm\'s aes key: %s'%Sm)
    print('injection check: %s\n'%(Sm==Sa))
    
    iva = key_gen()
    c = aes_cbc(Sa,msg,iva,decrypt=False)
    print('ALICE SEND')
    print('ciphertext: %s'%c)
    print('iv: %s'%iva)
    d = aes_cbc(Sm,c,iva)
    print('mitm decrypts: %s'%d)
    print('injection check: %s\n'%(d==msg))
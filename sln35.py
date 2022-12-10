import random, hashlib
from sln10 import aes_cbc
from sln11 import key_gen
from sln33 import modexp
from sln34 import aes_key_from_session

if __name__ == '__main__':
    print('===== g = 1 ATTACK =====')
    p,g = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff,1
    Sm = aes_key_from_session(1)
    print('predicted aes key: %s'%Sm)
    a,b = random.randint(1,p),random.randint(1,p)
    A,B = modexp(g,a,p),modexp(g,b,p)
    Sa,Sb = modexp(B,a,p),modexp(A,b,p)
    Sa,Sb = aes_key_from_session(Sa),aes_key_from_session(Sb)
    print('alice\'s aes key: %s'%Sa)
    print('bob\'s aes key: %s'%Sb)
    print('prediction check: %s\n'%(Sa==Sm))
    
    print('===== g = p ATTACK =====')
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = p
    Sm = aes_key_from_session(0)
    print('predicted aes key: %s'%Sm)
    a,b = random.randint(1,p),random.randint(1,p)
    A,B = modexp(g,a,p),modexp(g,b,p)
    Sa,Sb = modexp(B,a,p),modexp(A,b,p)
    Sa,Sb = aes_key_from_session(Sa),aes_key_from_session(Sb)
    print('alice\'s aes key: %s'%Sa)
    print('bob\'s aes key: %s'%Sb)
    print('prediction check: %s\n'%(Sa==Sm))
    
    print('===== g = p-1 ATTACK =====')
    p,g = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff,1
    Sm1 = aes_key_from_session(1)
    Sm2 = aes_key_from_session(-1)
    print('predicted aes key 1: %s'%Sm1)
    print('predicted aes key 2: %s'%Sm2)
    a,b = random.randint(1,p),random.randint(1,p)
    A,B = modexp(g,a,p),modexp(g,b,p)
    Sa,Sb = modexp(B,a,p),modexp(A,b,p)
    Sa,Sb = aes_key_from_session(Sa),aes_key_from_session(Sb)
    print('alice\'s aes key: %s'%Sa)
    print('bob\'s aes key: %s'%Sb)
    print('prediction check: %s\n'%(Sa in [Sm1,Sm2]))
    
    
from hashlib import sha256,pbkdf2_hmac
from sln36 import Server,Client

if __name__ == '__main__':
    N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g,k = 2,3
    I = 'admin@mail.com'
    P = 'P@ssw0rd!123'
    
    server = Server(N,g,k,I,P)
    salt,B = server.negotiate_key()
    mac = sha256(str(0).encode()).hexdigest()
    mac = pbkdf2_hmac('sha256',mac.encode(),salt.encode(),1)
    print('magic hash: %s'%mac)
    validation = server.validate_password(0,mac,True)
    print('validation on magic hash: %s'%validation)
    
import random
from hashlib import sha256,pbkdf2_hmac
from sln33 import modexp

class Server:
    
    def __init__(self,N,g,k,I,P):
        self.N,self.g,self.k,self.I,self.P = N,g,k,I,P
        self.salt = str(random.randint(0,self.N))
        x = int(sha256((self.salt+P).encode()).hexdigest(),16)
        self.v = modexp(g,x,N)
        
    def negotiate_key(self):
        self.b = random.randint(0,self.N-1)
        self.B = (self.k*self.v + modexp(self.g,self.b,self.N))%self.N
        return self.salt,self.B
    
    def validate_password(self,A,mac,report=False): 
        uH = sha256((format(A,'x')+format(self.B,'x')).encode()).hexdigest()
        u = int(uH,16)
        S = modexp(A*modexp(self.v,u,self.N),self.b,self.N)
        if report: print('S value: %s'%S)
        K = sha256(str(S).encode()).hexdigest()
        return pbkdf2_hmac('sha256',K.encode(),self.salt.encode(),1) == mac
        
        
class Client:
    
    def __init__(self,N,g,k,I,P): self.N,self.g,self.k,self.I,self.P = N,g,k,I,P
    
    def negotiate_key(self):
        self.a = random.randint(1,self.N)
        self.A = modexp(self.g,self.a,self.N)
        return self.I,self.A
    
    def send_password(self,B,salt): 
        uH = sha256((format(self.A,'x')+format(B,'x')).encode()).hexdigest()
        u = int(uH,16)
        xH = sha256((salt+self.P).encode()).hexdigest()
        x = int(xH,16)
        S = modexp(B-self.k*modexp(self.g,x,self.N),self.a+u*x,self.N)
        K = sha256(str(S).encode()).hexdigest()
        return pbkdf2_hmac('sha256',K.encode(),salt.encode(),1)


if __name__ == '__main__':
    N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g,k = 2,3
    I = 'admin@mail.com'
    P = 'P@ssw0rd!123'
    
    server = Server(N,g,k,I,P)
    client = Client(N,g,k,I,P)
    email,A = client.negotiate_key()
    salt,B = server.negotiate_key()
    mac = client.send_password(B,salt)
    validation = server.validate_password(A,mac)
    print('right password validation: %s'%validation)
    
    client = Client(N,g,k,I,'password')
    email,A = client.negotiate_key()   
    mac = client.send_password(B,salt)
    validation = server.validate_password(A,mac)
    print('wrong password validation: %s'%validation)
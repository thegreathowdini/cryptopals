import base64
from sln9 import pkcs7_pad
from sln10 import aes_cbc,xor_bytes
from sln11 import key_gen

def transaction_generate(f,t,a): 
    iv = key_gen()
    m = ('from=%s&to=%s&amount=%s'%(f,t,a)).encode()
    c = aes_cbc(key,m,iv,decrypt=False)[-len(key):]
    return base64.b64encode(m+iv+c)
    
def transaction_execute(t): 
    t = base64.b64decode(t)
    m,iv,c = t[:-2*len(key)],t[-2*len(key):-len(key)],t[-len(key):]
    h = aes_cbc(key,m,iv,decrypt=False)[-len(key):]
    if not h == c: return print('invalid signature')
    d = {p.split('=')[0]:p.split('=')[1] for p in m.decode().split('&')}
    print('transferred %s from %s to %s'%(d['amount'],d['from'],d['to']))
    
def transaction_list_generate(f,t,a): 
    m = ('from=%s&txlist=%s'%(f,';'.join('%s:%s'%(x,y) for x,y in zip(t,a)))).encode()
    c = aes_cbc(key,m,decrypt=False)[-len(key):]
    return base64.b64encode(m+c)
    
def transaction_list_execute(t): 
    t = base64.b64decode(t)
    m,c = t[:-len(key)],t[-len(key):]
    h = aes_cbc(key,m,decrypt=False)[-len(key):]
    if not h == c: return print('invalid signature')
    f,txlist = m.decode().split('&')
    f,txlist = f.split('=')[1],txlist.split('=')[1]
    for l in txlist.split(';'):
        t,a = l.split(':')
        print('transferred %s from %s to %s'%(a,f,t))

def limited_CBC_MAC(m): return aes_cbc(key,m,decrypt=False)[-len(key):]

if __name__ == '__main__':
    key = key_gen()
    
    print('===== LEGITIMATE TRANSACTION =====')
    t = transaction_generate('me','you','1M spacebucks')
    print('transaction data: %s'%t)
    transaction_execute(t)
    
    print('\n===== FORGED TRANSACTION =====')
    t = base64.b64decode(t)
    m,iv,c = t[:-2*len(key)],t[-2*len(key):-len(key)],t[-len(key):]
    iv = xor_bytes(xor_bytes(b'from=you&to=me&1',b'from=me&to=you&1'),iv)
    t = base64.b64encode(b'from=you&to=me&amount=1M spacebucks' + iv + c)
    print('transaction data: %s'%t)
    transaction_execute(t)
    
    print('\n===== LEGITIMATE TRANSACTION LIST =====')
    t = transaction_list_generate('target',['alice','bob','charlie'],['10','20','30'])
    print('transaction data: %s'%t)
    transaction_list_execute(t)
    
    print('\n===== FORGED TRANSACTION LIST =====')
    t = base64.b64decode(t)
    m,c = t[:-len(key)],t[-len(key):]
    m = pkcs7_pad(m)
    ex = b';attacker:1M spacebucks'
    c = limited_CBC_MAC(xor_bytes(ex[:len(c)],c)+ex[len(c):])
    t = base64.b64encode(m+ex+c)
    print('transaction data: %s'%t)
    transaction_list_execute(t)
    
import re,base64
from sln7 import aes_ecb
from sln9 import pkcs7_pad
from sln11 import key_gen

def cookie_parser(c): 
    c = aes_ecb(key,base64.b64decode(c)).decode()
    try: return {p.split('=')[0]:p.split('=')[1] for p in c.split('&')}
    except: return None
    
def profile_generator(email):
    if '=' in email or '&' in email: return None
    else: return base64.b64encode(aes_ecb(key,('email=%s&uid=10&role=user'%email).encode(),False))

if __name__ == '__main__':
    key = key_gen()
    n = 2
    base_length = len(base64.b64decode(profile_generator('A@mail.com')))
    while len(base64.b64decode(profile_generator('%s@mail.com'%('A'*n)))) == base_length: n += 1
    block_size = len(base64.b64decode(profile_generator('%s@mail.com'%('A'*n)))) - base_length
    
    email = 'A'*(block_size-len('email='))
    email += pkcs7_pad(b'admin',block_size).decode()
    email += '@mail.com'
    last_block = base64.b64decode(profile_generator(email))[block_size:2*block_size]  # 'admin' with padding
    
    email = 'A'*(n+4) + '@mail.com'
    c = base64.b64decode(profile_generator(email)) 
    c = c[:-block_size] + last_block
    c = base64.b64encode(c)
    print('forged cookie: %s'%c.decode())
    print('parsed: %s'%cookie_parser(c))
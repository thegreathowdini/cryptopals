import base64,random
from sln7 import aes_ecb
from sln9 import pkcs7_unpad
from sln11 import key_gen, mode_detector
from sln12 import find_next_byte

def harder_ecb_encryptor(p):
    p = prefix + p
    p += base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    return aes_ecb(key,p,False)

def harder_ecb_decryptor(encryptor):
    n,base_length = 1,len(encryptor(b''))
    while len(encryptor(b'A'*n)) == base_length: n += 1
    block_size = len(encryptor(b'A'*n)) - base_length
    
    A,B,i = encryptor(b'A'),encryptor(b'B'),0
    while (A[i]==B[i]): i += 1
    prefix_blocks = i//block_size
    
    for i in range(block_size): 
        r = find_next_byte(encryptor,b'',block_size,block_size*prefix_blocks+i)
        if r: prefix_bytes = block_size*prefix_blocks + i; break
    
    mode = mode_detector(encryptor)
    known = b''
    for n in range(len(encryptor(b''))): known += find_next_byte(encryptor,known,block_size,prefix_bytes)
    return block_size,prefix_bytes,mode,pkcs7_unpad(known)

if __name__ == '__main__':
    prefix = key_gen(random.randint(0,48))
    key = key_gen()
    block_size,prefix_bytes,mode,p = harder_ecb_decryptor(harder_ecb_encryptor)
    print('block size: %s'%block_size)
    print('prefix length: %s'%prefix_bytes)    
    print('mode: %s'%mode)
    print('\nplaintext: \n%s'%p.decode())
import base64
from sln7 import aes_ecb
from sln9 import pkcs7_unpad
from sln11 import key_gen, mode_detector

def simple_ecb_encryptor(p):
    p += base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    return aes_ecb(key,p,False)

def find_next_byte(encryptor,known,block_size,prefix_bytes=0):
    com_len = block_size*((len(known)+prefix_bytes)//block_size+1)
    payload = b'A'*(com_len-prefix_bytes-len(known)-1)
    target = encryptor(payload)[:com_len]
    for i in range(256):
        if encryptor(payload + known + bytes([i]))[:com_len] == target: return b'' if not i and encryptor(payload + known + bytes([1]))[:com_len] == target else bytes([i])
    return b''

def simple_ecb_decryptor(encryptor):
    n,base_length = 1,len(encryptor(b''))
    while len(encryptor(b'A'*n)) == base_length: n += 1
    block_size = len(encryptor(b'A'*n)) - base_length
    mode = mode_detector(encryptor)
    known = b''
    for n in range(len(encryptor(b''))): known += find_next_byte(encryptor,known,block_size)
    return block_size,mode,pkcs7_unpad(known)

if __name__ == '__main__':
    key = key_gen()
    block_size,mode,p = simple_ecb_decryptor(simple_ecb_encryptor)
    print('block size: %s'%block_size)
    print('mode: %s'%mode)
    print('\nplaintext: \n%s'%p.decode())
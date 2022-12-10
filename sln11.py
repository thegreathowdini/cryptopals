from Crypto import Random
from sln7 import aes_ecb
from sln10 import aes_cbc
import random

def key_gen(key_size=16): return Random.new().read(key_size)

def encryption_oracle(p):
    p = key_gen(random.randint(5,10)) + p + key_gen(random.randint(5,10))
    if random.randint(0,1): return aes_cbc(key_gen(),p,key_gen(),False)
    else: return aes_ecb(key_gen(),p,False)

def mode_detector(oracle,block_size=16):
    c = oracle(b'A'*64)
    chunks = [c[i*block_size:(i+1)*block_size] for i in range(len(c)//block_size)]
    return 'ECB' if len(chunks)-len(set(chunks)) else 'CBC'

if __name__ == '__main__': print('detector found: %s'%mode_detector(encryption_oracle))
    
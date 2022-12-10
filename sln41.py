from sln11 import key_gen
from sln39 import RSA,int_to_bytes,bytes_to_int


if __name__ == '__main__':
    p = key_gen()
    print('true plaintext: %s'%p)
    
    r = RSA(3,1024)
    c = r.encrypt(p)
    modified_c = int_to_bytes(8*bytes_to_int(c))
    modified_p = r.decrypt(modified_c)
    g = int_to_bytes(bytes_to_int(modified_p)//2)
    print('solved plaintext: %s'%g)
    
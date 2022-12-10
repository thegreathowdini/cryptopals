import base64,random
from sln10 import aes_cbc,xor_bytes
from sln11 import key_gen

def insecure_encryptor(key,p,decrypt=False): return aes_cbc(key,p,key,decrypt=decrypt)
    
if __name__ == '__main__':
    key = key_gen()
    message = insecure_encryptor(key,key_gen(5*len(key)))
   
    modified_message = message[:len(key)] + b'\x00'*len(key) + message[:len(key)] + message[3*len(key):]
    decrypted_modified_message = insecure_encryptor(key,modified_message,decrypt=True)
    
    extracted_key = xor_bytes(decrypted_modified_message[2*len(key):],decrypted_modified_message[:len(key)])
    
    print('extracted key: %s'%extracted_key)
    print('actual key: %s'%key)
    
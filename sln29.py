import struct,binascii
from sln11 import key_gen
from sln28 import sha1_mac,my_sha1

def get_padding(m): return b'\x80' + b'\x00'*((55-len(m))%64) + struct.pack('>Q',len(m)*8)

if __name__ == '__main__':
    key = key_gen()
    
    original_message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    original_hash = sha1_mac(original_message,key)
    print('original message: %s\n'%original_message)
    
    regs = struct.unpack('>5I',binascii.unhexlify(original_hash))
    for k in range(20):
        glue_padding = get_padding(b'A'*k+original_message)
        extended_message = original_message + glue_padding + b'admin=true'
        test_hash = my_sha1(b'admin=true',(k+len(extended_message))*8,regs[0],regs[1],regs[2],regs[3],regs[4])
        if test_hash == sha1_mac(extended_message,key): 
            print('forged signature for message: %s'%extended_message)
            print('signature: %s'%test_hash)
            break
    else: print('failed to find extension--increase key length range?'); quit()

    
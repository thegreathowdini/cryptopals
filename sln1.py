import binascii,base64
s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
p = binascii.unhexlify(s)
print('decoded: %s'%p)
print('b64 encoded: %s'%base64.b64encode(p))

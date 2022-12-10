from sln9 import pkcs7_unpad

s = b'ICE ICE BABY\x04\x04\x04\x04'
print('valid padding removed: %s'%pkcs7_unpad(s))
print('trying bad padding...')
s = b'ICE ICE BABY\x01\x02\x03\x04'
pkcs7_unpad(s)

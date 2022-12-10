from sln47 import bleichenbacher

l = 768
m = b'kick it, CC'
print('plaintext: %s'%bleichenbacher(l,m))
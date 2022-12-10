import base64,zlib
from sln10 import aes_cbc
from sln11 import key_gen

def request(p):
    r = 'POST / HTTP/1.1\n'
    r += 'Host: hapless.com\n'
    r += 'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n'
    r += 'Content-Length: ' + str(len(p)) + '\n\n'
    r += p
    return r

def oracle(p): return len(aes_cbc(key_gen(),zlib.compress(request(p).encode()),key_gen(),False))
    
if __name__ == '__main__':
    a = 'poiuytrewqlkjhgfdsamnbvcxzPOIUYTREWQLKJHGFDSAMNBVCXZ0987654321/=+\n'
    p,o = 'sessionid=',['']
    
    while 1:
        pad = ''
        while oracle(pad+p+o[0]) == oracle(p+o[0]): pad += 'A'
        d = {s+c:oracle(pad+p+s+c) for s in o for c in a}
        o = [c for c in d if d[c]==min(d.values())]
        if len(o) == 1: print('found so far: %s'%o[0])
        if len(o[0]) == 45: break
    print('done! cookie: %s'%([c for c in o if c[-1]=='\n'][0]))
    
def pkcs7_pad(b,block_size=16):
    n = -len(b)%block_size
    if not n: n = block_size
    return b + bytes([n])*n
    
def pkcs7_unpad(b): 
    if b[-1] < len(b) and all(c==b[-1] for c in b[-b[-1]:]): return b[:-b[-1]]
    else: raise Exception('Bad padding')
    
if __name__ == '__main__':
    b = b'YELLOW SUBMARINE'
    print(pkcs7_pad(b,20))
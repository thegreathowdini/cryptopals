import base64,random
from sln10 import aes_cbc
from sln11 import key_gen

def cookie_gen(s): 
    data = 'comment1=cooking%20MCs;userdata='+s.replace('=','').replace(';','')+';comment2=%20like%20a%20pound%20of%20bacon'
    return base64.b64encode(aes_cbc(key,data.encode(),iv,decrypt=False))
    
def admin_checker(c): 
    data = aes_cbc(key,base64.b64decode(c),iv)
    return b';admin=true;' in data,data
    
def bitflipper(a,b,c): return bytes([ord(a)^ord(b)^c])
    
if __name__ == '__main__':
    key,iv = key_gen(),key_gen()
    
    base_length,i = len(base64.b64decode(cookie_gen(''))),0
    while len(base64.b64decode(cookie_gen('A'*i))) == base_length: i += 1
    block_size = len(base64.b64decode(cookie_gen('A'*i)))-base_length
    
    def count_matching_blocks(n):
        c1,c2,i = base64.b64decode(cookie_gen('A'*(n+1))),base64.b64decode(cookie_gen('A'*n+'B')),0
        while c1[i] == c2[i]: i+=1
        return i//block_size        
    i,base_count = 1,count_matching_blocks(0)
    while count_matching_blocks(i) == base_count: i += 1
    untampered_cookie = base64.b64decode(cookie_gen('A'*i+'A'*block_size+'XadminXtrue'))
    result,data = admin_checker(base64.b64encode(untampered_cookie))
    print('unforged cookie data: %s\nadmin check: %s\n'%(data,result))
    
    start = (base_count+1)*block_size
    tampered_cookie = untampered_cookie[:start] + bitflipper('X',';',untampered_cookie[start]) + untampered_cookie[start+1:start+6] + bitflipper('X','=',untampered_cookie[start+6]) + untampered_cookie[start+7:]
    result,data = admin_checker(base64.b64encode(tampered_cookie))
    print('forged cookie data: %s\nadmin check: %s'%(data,result))
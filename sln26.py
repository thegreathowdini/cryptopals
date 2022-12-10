import base64,random
from sln11 import key_gen
from sln16 import bitflipper
from sln18 import aes_ctr

def cookie_gen(s): 
    data = 'comment1=cooking%20MCs;userdata='+s.replace('=','').replace(';','')+';comment2=%20like%20a%20pound%20of%20bacon'
    return base64.b64encode(aes_ctr(key,data.encode()))
    
def admin_checker(c): 
    data = aes_ctr(key,base64.b64decode(c))
    return b';admin=true;' in data,data
  
    
if __name__ == '__main__':
    key = key_gen()
    
    c1,c2,i = base64.b64decode(cookie_gen('A')),base64.b64decode(cookie_gen('B')),0
    while c1[i] == c2[i]: i+=1
    
    untampered_cookie = cookie_gen('xXadminXtrue')
    result,data = admin_checker(untampered_cookie)
    print('unforged cookie data: %s\nadmin check: %s\n'%(data,result))
    
    untampered_cookie = base64.b64decode(untampered_cookie)
    tampered_cookie = untampered_cookie[:i+1] + bitflipper('X',';',untampered_cookie[i+1]) + untampered_cookie[i+2:i+7] + bitflipper('X','=',untampered_cookie[i+7]) + untampered_cookie[i+8:]
    result,data = admin_checker(base64.b64encode(tampered_cookie))
    print('forged cookie data: %s\nadmin check: %s'%(data,result))
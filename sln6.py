import binascii,base64
from sln3 import hex_decode
from sln5 import repeating_key_xor

def hamming(a,b): return sum([u != v for x,y in zip(a,b) for u,v in zip(format(x,'08b'),format(y,'08b'))])
def break_vigenere(c): 
    best_edit_distance,key_length = 9999,0
    for n in range(1,40):
        chunks = [c[i*n:(i+1)*n] for i in range(len(c)//n)]
        test_edit_distance = sum([hamming(x,y) for x,y in zip(chunks[:-1],chunks[1:])])/(n*(len(chunks)-1))
        if test_edit_distance < best_edit_distance: best_edit_distance, key_length = test_edit_distance, n
    blocks, key = [[] for i in range(key_length)], []
    for i in range(len(c)): blocks[i%key_length].append(c[i])
    for block in blocks:
        best_score, best_key, best_plaintext = hex_decode(block,False)
        key.append(best_key)
    return key

if __name__ == '__main__':
    a = b'this is a test'
    b = b'wokka wokka!!!'
    print('hamming function test: %s'%(hamming(a,b)==37))

    c = base64.b64decode(open('files/6.txt','r').read())
    key = break_vigenere(c)
    
    print('probable key length: %s'%len(key))    
    print('key: %s'%(''.join([chr(i) for i in key])))
    print('\nplaintext:\n%s'%binascii.unhexlify(repeating_key_xor(key,c)).decode())

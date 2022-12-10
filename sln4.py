from sln3 import hex_decode

if __name__ == '__main__':
    d = open('files/4.txt','r').read().splitlines()
    best_score, best_key, best_plaintext, best_ciphertext = 0,'','',''
    for l in d: 
        score, key, plaintext = hex_decode(l)
        if score > best_score: best_score, best_key, best_plaintext, best_ciphertext = score, key, plaintext, l
        
    print('ciphertext: %s'%best_ciphertext)
    print('key: %s'%chr(best_key))
    print('plaintext: %s'%best_plaintext.decode())

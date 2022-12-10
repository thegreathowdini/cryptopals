def english_score(b): return sum([c in list(range(65,122))+[32] for c in b])/len(b)
def one_char_xor(k,s): return b''.join([bytes([k^c]) for c in s])
def hex_decode(s,hex=True):
    if hex: s = [int(s[j*2:(j+1)*2],16) for j in range(len(s)//2)]
    best_score, best_key, best_plaintext = 0,'',''
    for i in range(255): 
        d = one_char_xor(i,s)
        score = english_score(d)
        if score > best_score: best_score, best_key, best_plaintext = score, i, d
    return best_score, best_key, best_plaintext

if __name__ == '__main__':
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    best_score, best_key, best_plaintext = hex_decode(s)
    print('key: %s'%chr(best_key))
    print('plaintext: %s'%best_plaintext.decode())
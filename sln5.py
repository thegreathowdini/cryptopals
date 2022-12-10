def repeating_key_xor(k,p): return ''.join(['%02x'%(p[i]^k[i%len(k)]) for i in range(len(p))])

if __name__ == '__main__':
    s = '''Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal'''
    c = repeating_key_xor(b'ICE',s.encode())
    print('encoded: %s'%c)
    print('check: %s'%(c=='0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'))

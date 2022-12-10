import binascii

def xor_hexes(a,b): return ''.join(['%02x'%(x^y) for x,y in zip(binascii.unhexlify(a),binascii.unhexlify(b))])

if __name__ == '__main__':
    a = '1c0111001f010100061a024b53535009181c'
    b = '686974207468652062756c6c277320657965'
    r = xor_hexes(a,b)
    print('xor result: %s'%r)
    print('decoded: %s'%binascii.unhexlify(r))
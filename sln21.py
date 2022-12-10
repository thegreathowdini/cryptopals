import random

class MT19937:
    (w,n,m,r) = (32,624,397,31)
    a = 0x9908B0DF
    (u,d) = (11,0xFFFFFFFF)
    (s,b) = (7,0x9D2C5680)
    (t,c) = (15,0xEFC60000)
    l = 18
    lower_mask = (1 << r)-1
    upper_mask = (not lower_mask)&(2**w-1)
    f = 1812433253
    
    def __init__(self,seed):
        self.index = self.n
        self.mt = [seed]
        for i in range(1,self.n,1): self.mt.append((self.f*(self.mt[-1]^(self.mt[-1]>>(self.w-2)))+i)&(2**self.w-1))
        
    def extract_number(self):
        if self.index >= self.n: self.twist()
        y = self.mt[self.index]
        y ^= ((y >> self.u) & self.d)
        y ^= ((y << self.s) & self.b)
        y ^= ((y << self.t) & self.c)
        y ^= y >> self.l
        self.index += 1
        return y&(2**self.w-1)

    def twist(self):
        for i in range(self.n):
            x = (self.mt[i] & self.upper_mask) + (self.mt[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x%2: xA ^= self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xA
        self.index = 0
        pass
    
if __name__ == '__main__':
    seed = random.randint(0,99999)
    print('initialising MT19937 with seed %s'%seed)
    rng = MT19937(seed)
    print('extracting numbers: %s'%', '.join(str(rng.extract_number()) for _ in range(5)))
    rng = MT19937(seed)
    print('verifying determinism: %s'%', '.join(str(rng.extract_number()) for _ in range(5)))
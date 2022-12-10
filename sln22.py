import random,time
from sln21 import MT19937

def MT19937_brute(start_time,window,known_val):
    for i in range(window):
        test_rng = MT19937(start_time+i)
        if test_rng.extract_number() == known_val: return start_time+i
    return None

if __name__ == '__main__':
    start = int(time.time())
    middle = start + random.randint(40,1000)
    rng = MT19937(middle)
    end = middle + random.randint(40,1000)
    known_val = rng.extract_number()
    print('known value: %s'%known_val)
    
    seed = MT19937_brute(start,end-start,known_val)
    print('seed found: %s'%seed)
    test_rng = MT19937(seed)
    print('first generated value: %s'%test_rng.extract_number())
import time,threading,queue
from sln11 import key_gen
from sln28 import sha1_mac

def file_access(u):
    try: 
        d = {k.split('=')[0]:k.split('=')[1] for k in u.split('?')[1].split('&')}
        return insecure_compare(d['signature'],sha1_mac(key,d['file'].encode()))
    except: return 500

def insecure_compare(a,b):
    for x,y in zip(a,b):
        if x != y: return 500
        time.sleep(.05)
    if len(a) != len(b): return 500
    return 200

class W(threading.Thread):
    def __init__(self,c,k):
        threading.Thread.__init__(self)
        self.c = c
        self.k = k
    def run(self): 
        start = time.time()
        u = 'https://server.com/?file=%s&signature=%s'%(file,self.k+self.c)
        for _ in range(5): file_access(u)
        self.r = time.time() - start
    def join(self):
        threading.Thread.join(self)
        return (self.c,self.r)
        
if __name__ == '__main__':
    key = key_gen()
    file = 'test_file.txt'
    
    print('getting signature for %s'%file)
    print('true signature: %s'%sha1_mac(key,file.encode()))
    
    def test_sig(f,s): return file_access('https://server.com/?file=%s&signature=%s'%(file,s)) == 200
    
    a,k = 'poiuytrewqlkjhgfdsamnbvcxz0987654321',''
    while not test_sig(file,k):
        q,t = queue.Queue(),[]
        for c in a:
            w = W(c,k)
            w.daemon = True
            w.start()
            t.append(w)
        t = [b.join() for b in t]
        t = {p[0]:p[1] for p in t}
        k += max(t,key=lambda x:t[x])
        print('signature found so far: %s'%k)
    
    print('done!\n')
    u = 'https://server.com/?file=%s&signature=%s'%(file,k)
    print('file access url: %s'%u)
    print('server response: %s'%file_access(u))
    
    
    
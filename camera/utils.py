import time
class FPSLimiter:
    def __init__(self,fps):
        self.delay=1.0/fps
        self.last=time.time()
    def wait(self):
        now=time.time()
        diff=now-self.last
        if diff<self.delay:
            time.sleep(self.delay-diff)
        self.last=time.time()

"""Small in-memory measured service rate guard, not identity or authorization.

Bounds one running process; it does not claim a durable global spending cap or
replace the managed source budget, attestation, source policy or replay controls.
"""
import math
import threading
import time


class ServiceAdmission:
    def __init__(self,rate=4,burst=16,*,clock=None):
        if (type(rate) not in (int,float) or not math.isfinite(rate) or not 0<rate<=100
                or type(burst) is not int or not 1<=burst<=100):raise ValueError('service-rate')
        self.rate=rate;self.burst=burst;self._clock=clock or time.monotonic
        self._tokens=float(burst);self._last=self._clock();self._lock=threading.Lock()

    def admit(self):
        with self._lock:
            now=self._clock()
            if not math.isfinite(now) or now<self._last:return False
            self._tokens=min(self.burst,self._tokens+(now-self._last)*self.rate);self._last=now
            if self._tokens<1:return False
            self._tokens-=1;return True

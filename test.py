import time
from uos import urandom
from ecdsa import secp256r1


def timing_kP():
    d = int.from_bytes(urandom(37), 'big', False)
    start = time.ticks_ms()  # get millisecond counter
    Q = secp256r1.kP(d, secp256r1.P)
    delta = time.ticks_diff(time.ticks_ms(), start)  # compute time difference
    print(delta)


timing_kP()

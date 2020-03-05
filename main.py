import hid
import pyb
from u2f import u2f
from ctap2 import ctap2
from wink import init_timer


def loop():
    pyb.delay(100)
    h = hid.hid()
    init_timer()

    while True:
        cmd, data = h.receive()
        if cmd == hid.CTAPHID_MSG:
            h.send(cmd, u2f(data))
        elif cmd == hid.CTAPHID_CBOR:
            h.send(cmd, ctap2(data))


pyb.delay(100)
loop()

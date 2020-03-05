import pyb
from uos import urandom
from wink import setup_timer


SUCCESS = 0
ERR_INVALID_CMD = const(0x01)      # The command in the request is invalid
ERR_INVALID_PAR = const(0x02)      # The parameter(s) in the request is invalid
ERR_INVALID_LEN = const(0x03)      # The length field (BCNT) is invalid for the request
ERR_INVALID_SEQ = const(0x04)      # The sequence does not match expected value
ERR_MSG_TIMEOUT = const(0x05)      # The message has timed out
ERR_CHANNEL_BUSY = const(0x06)     # The device is busy for the requesting channel
ERR_LOCK_REQUIRED = const(0x0A)    # Command requires channel lock
ERR_INVALID_CHANNEL = const(0x0B)  # CID is not valid.
ERR_OTHER = const(0x7F)            # Unspecified error

CTAPHID_ERROR = const(0x3F)        # This command code is used in response messages only
CTAPHID_INIT =  const(0x06)
CTAPHID_MSG = const(0x03)
CTAPHID_WINK = const(0x08)
CTAPHID_CBOR = const(0x10)
CTAPHID_PING  = const(0x01)

PROTOCOL_VER = const(2)
MAJOR_DEV_VER = const(0)
MINOR_DEV_VER = const(1)
BUILD_DEV_VER = const(1)
CAPABILITIES = const(0x05)  # CAPABILITY_CBOR + CAPABILITY_WINK


class hid():
    PacketSize = const(64)

    def __init__(self):
        self.h = pyb.USB_HID()
        self.CID = b'\xff\xff\xff\xff'

    def receive(self, timeout=-1):
        sequence_counter = -1
        while True:
            req = self.h.recv(hid.PacketSize, timeout=timeout)
            print("rec:", req)
            if len(req) != hid.PacketSize:
                self.send_error(ERR_OTHER)
                sequence_counter = -1
                continue
            if req[:7] == b'\xff\xff\xff\xff\x86\x00\x08':
                # cmd == CTAPHID_INIT:
                self.hid_init(req[7:7+8])
                sequence_counter = -1
                continue
            if req[:4] != self.CID:
                self.send_error(ERR_INVALID_CHANNEL)
                sequence_counter = -1
                continue
            if sequence_counter == -1:
                if req[4] & 0x80 == 0:
                    self.send_error(ERR_INVALID_CMD)
                    continue
                bcnt = req[5]*256 + req[6]
                if bcnt > 7609:
                    self.send_error(ERR_INVALID_LEN)
                    continue
                cmd = req[4] & 0x7f
                data = req[7:7+bcnt]
            else:
                if req[4] != sequence_counter or sequence_counter == 128:
                    self.send_error(ERR_INVALID_SEQ)
                    sequence_counter = -1
                    continue
                data += req[5:5+bcnt-len(data)]
            if len(data) < bcnt:
                sequence_counter += 1
                continue
            else:
                if cmd == CTAPHID_PING:
                    self.ping(data)
                    sequence_counter = -1
                    continue
                elif cmd == CTAPHID_WINK:
                    if len(data) > 0:
                        self.send_error(ERR_INVALID_LEN)
                    else:
                        self.wink()
                    sequence_counter = -1
                    continue
                elif cmd == CTAPHID_MSG:
                    break
                elif cmd == CTAPHID_CBOR:
                    break
                else:
                    self.send_error(ERR_INVALID_CMD)
                    sequence_counter = -1
                    continue

        return cmd, data

    def send(self, cmd, data):
        L = len(data)
        response = self.CID + bytes((cmd | 0x80, L >> 8, L & 0xff)) + data
        print('resp:', response)
        sequence_counter = 0
        while True:
            if len(response) < hid.PacketSize:
                response += bytes(hid.PacketSize - len(response))
            self.h.send(response[:hid.PacketSize])
            pyb.delay(10)
            if len(response) > hid.PacketSize:
                response = self.CID \
                           + sequence_counter.to_bytes(1, 'big') \
                           + response[hid.PacketSize:]
                sequence_counter += 1
            else:
                break

    def send_error(self, error):
        self.send(CTAPHID_ERROR, error.to_bytes(1, 'big'))

    def hid_init(self, data):
        if len(data) != 8:
            self.send_error(ERR_INVALID_SEQ)
        else:
            while (True):
                CID = urandom(4)
                if CID != b'\xff\xff\xff\xff' and CID != b'\x00\x00\x00\x00':
                    break
            self.CID = b'\xff\xff\xff\xff'
            self.send(CTAPHID_INIT,
                      data + CID + bytes((PROTOCOL_VER, MAJOR_DEV_VER,
                                          ERR_INVALID_PAR, BUILD_DEV_VER,
                                          CAPABILITIES)))
            self.CID = CID

    def ping(self, data):
        self.send(CTAPHID_PING, data)

    def wink(self):
        setup_timer()
        self.send(CTAPHID_WINK, b'')

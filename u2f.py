from ucryptolib import aes
from uhashlib import sha256
from ecdsa import secp256r1, ecdsa_sign
from hmac import hmac_sha256
from keystore import KS_U2F
from up_check import up_check
from os import rmdir, listdir

SW_NO_ERROR                 = b'\x90\x00'
SW_CONDITIONS_NOT_SATISFIED = b'\x69\x85'
SW_WRONG_DATA               = b'\x6a\x80'
SW_WRONG_LENGTH             = b'\x67\x00'
SW_CLA_NOT_SUPPORTED        = b'\x6e\x00'
SW_INS_NOT_SUPPORTED        = b'\x6d\x00'

CERTIFICATE_DER = b"0\x82\x01m0\x82\x01\x12\xa0\x03\x02\x01\x02\x02\t\x00\xad\x16%v=1\xe2\xf00\n\x06\x08*\x86H\xce=\x04\x03\x020\x111\x0f0\r\x06\x03U\x04\x03\x0c\x06FidoBt0\x1e\x17\r190307143256Z\x17\r490418143256Z0\x111\x0f0\r\x06\x03U\x04\x03\x0c\x06FidoBt0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04\xcb\xf8G\xb3\x96\xe6\xa0-\xe3\xbe\xb5G\xa7\xa3\xd6T\x023\xa3\x96\x85,\x01@r*Y'\x944l=\xaefv\xa2x\x835\x88=\xcb\x92(\x0b\xc6\xbf\xeb\xd8\xca\x05\\\x0e#\x96\x9d,0S\xd2\xf5\x1a\xea\xb4\xa3S0Q0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xe7S%C\x89\xb4\x9b\\\x11\\\xb2\x1d\xc91x@\x94-\xe0=0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xe7S%C\x89\xb4\x9b\\\x11\\\xb2\x1d\xc91x@\x94-\xe0=0\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03I\x000F\x02!\x00\xb1/4\t\xe4\x01\xe7\xf1T\xfd~m0\x97\xb68V0\xc9\xe76C\xbd\xfeL\x01!\xbe\xc2_\xa5Z\x02!\x00\x84\x84}\xb6\xe9\x9d\x1a\x9e\xf9r\xe6)a\x95\xa1e\x8dv\x16\xec<\x9c5KV\x18\x85\xd0\xcejqC"
PRIVATE_EC_KEY = const(0x0cd6a26e9525d2c18d5d3e32f1d56eca1f30af687d185342f5ac4f38712c9de3)

MODE_CBC = const(2)

KEY_HANDLE_LENGTH = const(96)

ks_u2f = KS_U2F()


def u2f(apdu):
    global ks_u2f
    if 'RESET_U2F' in listdir():
        rmdir('RESET_U2F')
        ks_u2f = KS_U2F()
    if len(apdu) < 5:
        return SW_WRONG_LENGTH
    cmd, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
    lc = le = 0
    req = b''

    if len(apdu) == 5:
        le = apdu[4]
    elif len(apdu) == 6:
        if apdu[4] == 1:
            lc = 1
            req = apdu[5:]
        else:
            le = apdu[4] * 256 + apdu[5] if apdu[4] | apdu[5] > 0 else 2**16
    else:
        if apdu[4] > 0:
            lc = apdu[4]
            req, rest = apdu[5:5 + lc], apdu[5 + lc:]
            if len(req) != lc:
                return SW_WRONG_LENGTH
            if len(rest) == 1:
                le = rest[0] if rest[0] > 0 else 256
            elif len(rest) > 1:
                return SW_WRONG_LENGTH
        else:
            lc = apdu[5] * 256 + apdu[6]
            req, rest = apdu[7:7 + lc], apdu[7 + lc:]
            if len(req) != lc:
                return SW_WRONG_LENGTH
            if len(rest) == 2:
                if rest[0] | rest[1] > 0:
                    le = rest[0] * 256 + rest[1]  # however, le is never used
                else:
                    le = 2**16
            elif len(rest) > 2:
                return SW_WRONG_LENGTH

    if cmd != 0:
        return SW_CLA_NOT_SUPPORTED
    elif ins == 1:
        return u2f_register(req)
    elif ins == 2:
        return u2f_authenticate(p1, req)
    elif ins == 3:
        # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#other-messages
        return b'U2F_V2' + SW_NO_ERROR
    else:
        return SW_INS_NOT_SUPPORTED


def u2f_register(req):
    # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-messages
    if len(req) != 64:
        return SW_WRONG_LENGTH
    # ec key genaration
    d, Q = secp256r1.keyGen()
    user_public_key = b'\x04' + Q.x.to_bytes(32, 'big') \
                              + Q.y.to_bytes(32, 'big')
    key_handle = enc_key_handle(d.to_bytes(32, 'big') + req[32:])

    s = sha256(b'\x00' + req[32:] + req[:32] + key_handle + user_public_key)
    h = int.from_bytes(s.digest(), 'big', False)
    signature = ecdsa_sign(secp256r1, PRIVATE_EC_KEY, h)
    return b'\x05' \
           + user_public_key \
           + KEY_HANDLE_LENGTH.to_bytes(1, 'big') \
           + key_handle \
           + CERTIFICATE_DER \
           + signature \
           + SW_NO_ERROR


def u2f_authenticate(control_byte, req):
    # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#authentication-messages
    global ks_u2f
    L = req[64]
    if L != KEY_HANDLE_LENGTH:
        return SW_WRONG_DATA
    if len(req) != 64 + 1 + L:
        return SW_CONDITIONS_NOT_SATISFIED
    if control_byte not in (0x03, 0x07, 0x08):
        return SW_CONDITIONS_NOT_SATISFIED
    key_handle = dec_key_handle(req[65:], req[32:64])
    if key_handle == b'':
        return SW_WRONG_DATA
    if control_byte == 0x07:  # check-only
        return SW_CONDITIONS_NOT_SATISFIED
    user_presemce = b'\x00'
    if control_byte == 0x03:  # enforce-user-presence-and-sign
        if (up_check() is False):
            return SW_CONDITIONS_NOT_SATISFIED
        user_presemce = b'\x01'
    private_key = int.from_bytes(key_handle[:32], 'big', False)
    ks_u2f.COUNTER = (ks_u2f.COUNTER + 1) % 0x0100000000
    cb = ks_u2f.COUNTER.to_bytes(4, 'big')
    s = sha256(req[32:64] + user_presemce + cb + req[:32])
    h = int.from_bytes(s.digest(), 'big', False)
    signature = ecdsa_sign(secp256r1, private_key, h)
    return user_presemce + cb + signature + SW_NO_ERROR


def enc_key_handle(data):
    global ks_u2f
    enc = aes(ks_u2f.AES_KEY, MODE_CBC, ks_u2f.AES_IV)
    cipher = enc.encrypt(data)
    return cipher + hmac_sha256(ks_u2f.KEY_5C, ks_u2f.KEY_36, cipher)


def dec_key_handle(data, application_parameter):
    global ks_u2f
    if len(data) != KEY_HANDLE_LENGTH:
        return b''
    if data[-32:] != hmac_sha256(ks_u2f.KEY_5C, ks_u2f.KEY_36, data[:-32]):
        return b''
    dec = aes(ks_u2f.AES_KEY, MODE_CBC, ks_u2f.AES_IV)
    m = dec.decrypt(data[:-32])
    if m[32:] != application_parameter:
        return b''
    return m[:32]  # dec.decrypt(data[:32])

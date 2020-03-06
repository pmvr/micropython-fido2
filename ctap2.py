from time import ticks_ms, ticks_diff
from uhashlib import sha256
from ucryptolib import aes
from ctap_errors import *
from ecdsa import secp256r1, ecdsa_sign, point
from cbor import decode, encode
import cbor_ctap_parameters as ccp
from up_check import up_check
from hmac import hmac_sha256
from keystore import KS_CTAP2, KS_PIN
from uos import rmdir, mkdir, listdir, remove, urandom


CERTIFICATE_DER = b'0\x82\x02\x1a0\x82\x01\xbf\xa0\x03\x02\x01\x02\x02\t\x00\xdf\x15s\xf4HU\x18\xcb0\n\x06\x08*\x86H\xce=\x04\x03\x020z1\x0b0\t\x06\x03U\x04\x06\x13\x02DE1\x130\x11\x06\x03U\x04\x08\x0c\nSome-State1!0\x1f\x06\x03U\x04\n\x0c\x18Internet Widgits Pty Ltd1"0 \x06\x03U\x04\x0b\x0c\x19Authenticator Attestation1\x0f0\r\x06\x03U\x04\x03\x0c\x06FidoBt0 \x17\r200225160153Z\x18\x0f20500408160153Z0z1\x0b0\t\x06\x03U\x04\x06\x13\x02DE1\x130\x11\x06\x03U\x04\x08\x0c\nSome-State1!0\x1f\x06\x03U\x04\n\x0c\x18Internet Widgits Pty Ltd1"0 \x06\x03U\x04\x0b\x0c\x19Authenticator Attestation1\x0f0\r\x06\x03U\x04\x03\x0c\x06FidoBt0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04\xcb\xf8G\xb3\x96\xe6\xa0-\xe3\xbe\xb5G\xa7\xa3\xd6T\x023\xa3\x96\x85,\x01@r*Y\'\x944l=\xaefv\xa2x\x835\x88=\xcb\x92(\x0b\xc6\xbf\xeb\xd8\xca\x05\\\x0e#\x96\x9d,0S\xd2\xf5\x1a\xea\xb4\xa3,0*0\t\x06\x03U\x1d\x13\x04\x020\x000\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xe7S%C\x89\xb4\x9b\\\x11\\\xb2\x1d\xc91x@\x94-\xe0=0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03I\x000F\x02!\x00\xb5ZV.o\'\xc0n`\xc9l\xc0\x18\x00\xc2\x1f\x93_\xaaUR\xa3\x87\xcf\xbcA\x8eI\x10\x1bp\x99\x02!\x00\x9c\xea\x17a\x80\x1c#\xb1\xceN1]9\xc8\x11\x0f\xc6\x1e\xd6\xe0\xbd\xa0g(eh\xd3\x8dMA\xdd\xeb'
PRIVATE_EC_KEY = const(0x0cd6a26e9525d2c18d5d3e32f1d56eca1f30af687d185342f5ac4f38712c9de3)
MODE_CBC = const(2)


# authenticator API: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api
authenticatorMakeCredential   = const(0x01)
authenticatorGetAssertion     = const(0x02)
authenticatorGetInfo          = const(0x04)
authenticatorClientPIN        = const(0x06)
authenticatorReset            = const(0x07)
authenticatorGetNextAssertion = const(0x08)
authenticatorVendorFirst      = const(0x40)
authenticatorVendorLast       = const(0xbf)

# variables for managing next assertions
NUMBEROFCREDENTIALS = 0
CREDENTIALCOUNTER = 0
REM_GETASSERTION_PARAMETERS = []
REM_GETASSERTION_PARAMETERS_COMMON = []
REM_LAST_CMD = None
NEXT_CREDENTIAL_TIMER = ticks_ms()

# PIN retry management
PIN_CONSECUTIVE_RETRIES = 0

# keystores
ks_ctap2 = KS_CTAP2()
ks_pin = KS_PIN()


def ctap2(command):
    global ks_ctap2, ks_pin, REM_LAST_CMD
    if 'RESET_CTAP2' in listdir():  # reload keystore?
        rmdir('RESET_CTAP2')
        ks_ctap2 = KS_CTAP2()
    if 'RESET_PIN' in listdir():  # reload keystore?
        rmdir('RESET_PIN')
        ks_pin = KS_PIN()
    if len(command) == 0:
        return CTAP1_ERR_INVALID_LENGTH
    cmd, data = command[0], command[1:]
    REM_LAST_CMD = cmd
    if cmd == authenticatorGetInfo:
        if len(data) > 0:
            return CTAP1_ERR_INVALID_LENGTH
        return getInfo()
    elif cmd == authenticatorMakeCredential:
        if len(data) == 0:
            return CTAP1_ERR_INVALID_LENGTH
        return makeCredential(data)
    elif cmd == authenticatorGetAssertion:
        if len(data) == 0:
            return CTAP1_ERR_INVALID_LENGTH
        return getAssertion(data)
    elif cmd == authenticatorGetNextAssertion:
        if len(data) > 0:
            return CTAP1_ERR_INVALID_LENGTH
        return getNextAssertion()
    elif cmd == authenticatorClientPIN:
        if len(data) == 0:
            return CTAP1_ERR_INVALID_LENGTH
        return clientPIN(data)
    elif cmd == authenticatorReset:
        if len(data) > 0:
            return CTAP1_ERR_INVALID_LENGTH
        return reset()
    else:
        return CTAP2_ERR_OPERATION_DENIED


def getInfo():
    global ks_ctap2
    return CTAP2_OK + encode({1: ['FIDO_2_0', 'U2F_V2'],
                              3: ks_ctap2.AAGUID,
                              4: {'rk': True, 'clientPin': isPINset()},
                              6: [1]
                              })


def makeCredential(data):
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
    global ks_ctap2
    try:
        data = decode(data)
    except ValueError:
        return CTAP2_ERR_INVALID_CBOR
    # verify structure of parameter for authenticatorMakeCredential
    ret = ccp.authenticatorMakeCredential.verify(data)
    if ret != CTAP2_OK:
        return ret
    # user description
    user_description = {'id': data[3]['id']}
    for key in ('displayName', 'name', 'icon'):
        if key in data[3]:
            user_description[key] = data[3][key]
    rpId_user_description = encode([data[2]['id'], user_description])
    if not {'alg': -7, 'type': 'public-key'} in data[4]:  # ES256
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM
    if 5 in data:   # excludeList
        for x in data[5]:
            if x['type'] != 'public-key':
                continue
            if dec_key_handle(x['id']) != b'':
                return CTAP2_ERR_CREDENTIAL_EXCLUDED
    rk, uv, up = False, False, True  # default options
    if 7 in data:   # Map of authenticator options
        rk = data[7].get('rk', False)
        uv = data[7].get('uv', False)
        up = data[7].get('up', True)
        if uv is True:
            return CTAP2_ERR_UNSUPPORTED_OPTION
        if up is False:
            return CTAP2_ERR_INVALID_OPTION
    FLAGS = 0x40  # ED | AT | 0 | 0 | 0 | uv | 0 | up
    if isPINset():
        if 8 not in data or 9 not in data:  # pinAuth
            return CTAP2_ERR_PIN_REQUIRED
        if verifyPIN(data[8], data[1]) is False:
            return CTAP2_ERR_PIN_AUTH_INVALID
        else:
            FLAGS |= 0x04
    # make credential
    # user presence check
    if (up_check() is False):
        return CTAP2_ERR_OPERATION_DENIED
    FLAGS = int(FLAGS | 0x01).to_bytes(1, 'big')
    # hash rpid
    s = sha256(bytes(data[2]['id'], 'utf8'))
    rp_id_hash = s.digest()
    # ec key genaration
    d, Q = secp256r1.keyGen()
    if secp256r1.verify_point(Q) is False:
        return CTAP1_ERR_OTHER
    cose_key = encode({1: 2,   # kty: EC2 key type
                       3: -7,  # alg: ES256 signature algorithm
                      -1: 1,   # crv: P-256 curve
                      -2: Q.x.to_bytes(32, 'big'),  # x-coordinate
                      -3: Q.y.to_bytes(32, 'big')   # y-coordinate
                       })
    # generate key handle
    key_handle = enc_key_handle(d.to_bytes(32, 'big') + rpId_user_description)
    Lb = len(key_handle).to_bytes(2, 'big')
    # increase signature counter
    ks_ctap2.COUNTER = (ks_ctap2.COUNTER + 1) % 0x0100000000
    cb = ks_ctap2.COUNTER.to_bytes(4, 'big')
    # authenticator data: https://www.w3.org/TR/webauthn/#fig-attStructs
    auth_data = rp_id_hash + FLAGS + cb + ks_ctap2.AAGUID \
        + Lb + key_handle + cose_key
    # compute signature
    s = sha256(auth_data + data[1])  # auth_data + client_data_hash
    h = int.from_bytes(s.digest(), 'big', False)
    signature = ecdsa_sign(secp256r1, PRIVATE_EC_KEY, h)

    if rk is True:
        if ks_ctap2.save_rk(data[2]['id'], data[3]['id'], key_handle) is False:
            return CTAP2_ERR_KEY_STORE_FULL

    # https://www.w3.org/TR/webauthn/#sctn-attestation
    return CTAP2_OK + encode({1: 'packed',
                              2: auth_data,
                              3: {'alg': -7,
                                  'sig': signature, 'x5c': [CERTIFICATE_DER]}
                              })


def getAssertion(data):
    global ks_ctap2
    global NUMBEROFCREDENTIALS, CREDENTIALCOUNTER
    global REM_GETASSERTION_PARAMETERS, NEXT_CREDENTIAL_TIMER
    global REM_GETASSERTION_PARAMETERS_COMMON
    try:
        data = decode(data)
    except ValueError:
        return CTAP2_ERR_INVALID_CBOR
    # verify structure of parameter for authenticatorGetAssertion
    ret = ccp.authenticatorGetAssertion.verify(data)
    if ret != CTAP2_OK:
        return ret

    allowList = []
    len_allowList = 0
    useRK = False
    if 3 in data:   # allowList
        len_allowList = len(data[3])
        for pkc_descriptor in data[3]:
            if pkc_descriptor['type'] != 'public-key':
                continue
            allowList.append(pkc_descriptor['id'])
    if (3 not in data) or ((3 in data) and (len_allowList == 0)):
        # search for residential keys
        for key_handle in ks_ctap2.load_rk(data[1]):
            useRK = True
            allowList.append(key_handle)
    if not allowList:
        return CTAP2_ERR_NO_CREDENTIALS
    # get options
    uv, up = False, True  # default options
    if 5 in data:   # Map of authenticator options
        if 'rk' in data[5]:
            return CTAP2_ERR_UNSUPPORTED_OPTION
        uv = data[5].get('uv', False)
        up = data[5].get('up', True)
        if uv is True:
            return CTAP2_ERR_UNSUPPORTED_OPTION
    FLAGS = 0  # ED | AT | 0 | 0 | 0 | uv | 0 | up
    if isPINset():
        if 6 not in data or 7 not in data:  # pinAuth
            return CTAP2_ERR_PIN_REQUIRED
        if verifyPIN(data[6], data[2]) is False:
            return CTAP2_ERR_PIN_AUTH_INVALID
        else:
            FLAGS |= 0x04
    # make assertion
    REM_GETASSERTION_PARAMETERS.clear()
    for credId in allowList:
        key_data = dec_key_handle(credId)
        if key_data == b'':
            continue
        try:
            rpId, user_description = decode(key_data[32:])
        except ValueError:
            continue
        if rpId != data[1]:
            continue  # rpId does not match
        d = int.from_bytes(key_data[:32], 'big', False)
        if FLAGS & 0x04 == 0:
            # uv=PIN not done: remove all optional user informations
            user_description = {'id': user_description['id']}
        REM_GETASSERTION_PARAMETERS.append([d, user_description, credId])
    NUMBEROFCREDENTIALS = len(REM_GETASSERTION_PARAMETERS)
    if not REM_GETASSERTION_PARAMETERS:
        return CTAP2_ERR_NO_CREDENTIALS
    d, user_description, credentialID = REM_GETASSERTION_PARAMETERS.pop()
    # user presence check
    if up is True:
        if (up_check() is False):
            return CTAP2_ERR_OPERATION_DENIED
        FLAGS |= 1
    # rpIdHash
    s = sha256(bytes(data[1], 'utf8'))
    rp_id_hash = s.digest()
    # flags
    FLAGS = int(FLAGS).to_bytes(1, 'big')
    # increase signature counter
    ks_ctap2.COUNTER = (ks_ctap2.COUNTER + 1) % 0x0100000000
    cb = ks_ctap2.COUNTER.to_bytes(4, 'big')
    # authenticator data: https://www.w3.org/TR/webauthn/#table-authData
    auth_data = rp_id_hash + FLAGS + cb
    # compute signature
    s = sha256(auth_data + data[2])  # auth_data + client_data_hash
    h = int.from_bytes(s.digest(), 'big', False)
    signature = ecdsa_sign(secp256r1, d, h)
    if not REM_GETASSERTION_PARAMETERS:
        REM_GETASSERTION_PARAMETERS_COMMON = rp_id_hash, data[2], FLAGS, useRK
    CREDENTIALCOUNTER = 1
    NEXT_CREDENTIAL_TIMER = ticks_ms()
    # https://www.w3.org/TR/webauthn/#sctn-attestation
    ret = {1: {'id': credentialID, 'type': 'public-key'},
           2: auth_data,
           3: signature}
    if useRK is True:
        ret[4] = user_description
    if NUMBEROFCREDENTIALS > 1:
        ret[5] = NUMBEROFCREDENTIALS
    return CTAP2_OK + encode(ret)


def getNextAssertion():
    global ks_ctap2
    global NEXT_CREDENTIAL_TIMER, REM_GETASSERTION_PARAMETERS
    global CREDENTIALCOUNTER, NUMBEROFCREDENTIALS
    global REM_GETASSERTION_PARAMETERS_COMMON, REM_LAST_CMD
    if not REM_GETASSERTION_PARAMETERS:
        return CTAP2_ERR_NOT_ALLOWED
    if REM_LAST_CMD not in(authenticatorGetAssertion, authenticatorGetNextAssertion):
        return CTAP2_ERR_NOT_ALLOWED
    if CREDENTIALCOUNTER >= NUMBEROFCREDENTIALS:
        return CTAP2_ERR_NOT_ALLOWED
    if ticks_diff(ticks_ms(), NEXT_CREDENTIAL_TIMER) > 30000:
        return CTAP2_ERR_NOT_ALLOWED
    d, user_description, credentialID = REM_GETASSERTION_PARAMETERS.pop()
    rp_id_hash, clientDataHash, FLAGS, useRK = REM_GETASSERTION_PARAMETERS_COMMON
    # increase signature counter
    ks_ctap2.COUNTER = (ks_ctap2.COUNTER + 1) % 0x0100000000
    cb = ks_ctap2.COUNTER.to_bytes(4, 'big')
    # authenticator data: https://www.w3.org/TR/webauthn/#table-authData
    auth_data = rp_id_hash + FLAGS + cb
    # compute signature
    s = sha256(auth_data + clientDataHash)  # auth_data + client_data_hash
    h = int.from_bytes(s.digest(), 'big', False)
    signature = ecdsa_sign(secp256r1, d, h)
    CREDENTIALCOUNTER += 1
    NEXT_CREDENTIAL_TIMER = ticks_ms()
    ret = {1: {'id': credentialID, 'type': 'public-key'},
           2: auth_data,
           3: signature}
    if useRK is True:
        ret[4] = user_description
    return CTAP2_OK + encode(ret)


def enc_key_handle(data):
    # add padding data 80 00 00 ...
    enc = aes(ks_ctap2.AES_KEY, MODE_CBC, ks_ctap2.AES_IV)
    cipher = enc.encrypt(data + b'\x80' + bytes(-(1 + len(data)) % 16))
    return cipher + hmac_sha256(ks_ctap2.KEY_5C, ks_ctap2.KEY_36, cipher)


def dec_key_handle(data):
    if len(data) < 64 or len(data) % 16 > 0:
        return b''
    if data[-32:] != hmac_sha256(ks_ctap2.KEY_5C, ks_ctap2.KEY_36, data[:-32]):
        return b''
    dec = aes(ks_ctap2.AES_KEY, MODE_CBC, ks_ctap2.AES_IV)
    m = dec.decrypt(data[:-32])
    # remove padding 80 00 00 ...
    for i in range(len(m) - 1, 31, -1):
        if m[i] == 0x80:
            return m[:i]
        elif m[i] == 0x00:
            continue
        else:
            return b''  # wrong padding
    return b''


def reset():
    global PIN_CONSECUTIVE_RETRIES
    # user presence required
    if (up_check() is False):
        return CTAP2_ERR_OPERATION_DENIED
    PIN_CONSECUTIVE_RETRIES = 0
    dir = listdir()
    for fn in dir:
        if fn.endswith('.keystore'):
            remove(fn)
    for fn in ('RESET_CTAP2', 'RESET_PIN', 'RESET_U2F'):
        if fn not in dir:
            mkdir(fn)
    return CTAP2_OK


def clientPIN(data):
    global ks_pin, PIN_CONSECUTIVE_RETRIES
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN
    try:
        data = decode(data)
    except ValueError:
        return CTAP2_ERR_INVALID_CBOR
    ret = ccp.authenticatorClientPIN.verify(data)
    if ret != CTAP2_OK:
        return ret
    if data[2] == 0x01:  # getRetries
        return CTAP2_OK + encode({3: ks_pin.PIN_RETRIES})
    elif data[2] == 0x02:  # getKeyAgreement
        return CTAP2_OK + encode({1: {1: 2,   # kty: EC2 key type
                                      3: -25,  # alg: ECDH-ES+HKDF-256
                                      -1: 1,   # crv: P-256 curve
                                      # x-coordinate
                                      -2: ks_pin.DH_PK_x,
                                      # y-coordinate
                                      -3: ks_pin.DH_PK_y
                                      }
                                  })
    elif data[2] in (0x03, 0x04, 0x05):
        # verify parameters for setPIN, changePIN, getPINToken
        if 3 not in data:  # platformKeyAgreementKey
            return CTAP2_ERR_MISSING_PARAMETER
        if (data[2] in (0x03, 0x04)):
            if 4 not in data or 5 not in data:  # pinAuth, newPinEnc
                return CTAP2_ERR_MISSING_PARAMETER
        if (data[2] in (0x04, 0x05)):
            if 6 not in data:  # pinHashEnc
                return CTAP2_ERR_MISSING_PARAMETER
        if (data[2] == 0x03 and ks_pin.PIN != b'') \
           or (data[2] in (0x04, 0x05) and ks_pin.PIN == b''):
            # either setPIN command and PIN already set
            # or changePIN/getPINToken command and PIN not yet set
            return CTAP2_ERR_PIN_AUTH_INVALID
        Q = point(int.from_bytes(data[3][-2], 'big', False),
                  int.from_bytes(data[3][-3], 'big', False))
        if secp256r1.verify_point(Q) is False:
            return CTAP1_ERR_OTHER
        # compute shared secret as SHA-256(Q.x)
        d = int.from_bytes(ks_pin.DH_SK, 'big', False)
        shared_secret = sha256(
            secp256r1.kP(d, Q).x.to_bytes(32, 'big')).digest()
        k5c = bytes((c ^ 0x5c for c in shared_secret)) + b'\x5c' * 32
        k36 = bytes((c ^ 0x36 for c in shared_secret)) + b'\x36' * 32
        if data[2] == 0x03:  # setPIN
            # Authenticator verifies pinAuth by generating
            # LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
            # and matching against input pinAuth parameter.
            if hmac_sha256(k5c, k36, data[5])[:16] != data[4]:
                return CTAP2_ERR_PIN_AUTH_INVALID
            # Authenticator decrypts newPinEnc using above "sharedSecret"
            # producing newPin and checks newPin length against minimum
            # PIN length of 4 bytes.
            return set_new_pin(shared_secret, data[5])
        elif data[2] == 0x04:  # changePIN
            # If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            if ks_pin.PIN_RETRIES == 0:
                return CTAP2_ERR_PIN_BLOCKED
            if PIN_CONSECUTIVE_RETRIES == 3:
                return CTAP2_ERR_PIN_AUTH_BLOCKED
            # Authenticator verifies pinAuth by generating
            # LEFT(HMAC-SHA-256(sharedSecret, newPinEnc || pinHashEnc), 16)
            # and matching against input pinAuth parameter.
            if hmac_sha256(k5c, k36, data[5] + data[6])[:16] != data[4]:
                return CTAP2_ERR_PIN_AUTH_INVALID
            # Authenticator decrements the retries counter by 1.
            ks_pin.PIN_RETRIES -= 1
            PIN_CONSECUTIVE_RETRIES += 1
            ks_pin.save_keystore()
            # Authenticator decrypts pinHashEnc and verifies against its
            # internal stored LEFT(SHA-256(curPin), 16).
            if len(data[6]) != 16:
                return CTAP1_ERR_OTHER
            dec = aes(shared_secret, MODE_CBC, bytes(16))
            if dec.decrypt(data[6]) != ks_pin.PIN_DIGEST:
                if ks_pin.PIN_RETRIES == 0:
                    return CTAP2_ERR_PIN_BLOCKED
                elif PIN_CONSECUTIVE_RETRIES == 3:
                    return CTAP2_ERR_PIN_AUTH_BLOCKED
                else:
                    return CTAP2_ERR_PIN_INVALID
            # Authenticator sets the retries counter to 8.
            ks_pin.PIN_RETRIES = ks_pin.PIN_MAX_RETRIES
            ks_pin.save_keystore()
            PIN_CONSECUTIVE_RETRIES = 0
            # Authenticator decrypts newPinEnc using above "sharedSecret"
            # producing newPin and checks newPin length against minimum
            # PIN length of 4 bytes.
            return set_new_pin(shared_secret, data[5])
        elif data[2] == 0x05:  # getPINToken
            # If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            if ks_pin.PIN_RETRIES == 0:
                return CTAP2_ERR_PIN_BLOCKED
            if PIN_CONSECUTIVE_RETRIES == 3:
                return CTAP2_ERR_PIN_AUTH_BLOCKED
            # Authenticator decrements the retries counter by 1.
            ks_pin.PIN_RETRIES -= 1
            ks_pin.save_keystore()
            PIN_CONSECUTIVE_RETRIES += 1
            # Authenticator decrypts pinHashEnc and verifies against its
            # internal stored LEFT(SHA-256(curPin), 16).
            if len(data[6]) != 16:
                return CTAP1_ERR_OTHER
            dec = aes(shared_secret, MODE_CBC, bytes(16))
            if dec.decrypt(data[6]) != ks_pin.PIN_DIGEST:
                if ks_pin.PIN_RETRIES == 0:
                    return CTAP2_ERR_PIN_BLOCKED
                elif PIN_CONSECUTIVE_RETRIES == 3:
                    return CTAP2_ERR_PIN_AUTH_BLOCKED
                else:
                    return CTAP2_ERR_PIN_INVALID
            # Authenticator sets the retries counter to 8.
            ks_pin.PIN_RETRIES = ks_pin.PIN_MAX_RETRIES
            ks_pin.save_keystore()
            PIN_CONSECUTIVE_RETRIES = 0
            # Authenticator returns encrypted pinToken using
            # "sharedSecret": AES256-CBC(sharedSecret, IV=0, pinToken).
            ks_pin.PIN_TOKEN = urandom(16)
            ks_pin.save_keystore()
            enc = aes(shared_secret, MODE_CBC, bytes(16))
            return CTAP2_OK + encode({2: enc.encrypt(ks_pin.PIN_TOKEN)})


def set_new_pin(shared_secret, newPinEnc):
    global ks_pin, PIN_CONSECUTIVE_RETRIES
    # Authenticator decrypts newPinEnc using above "sharedSecret"
    if len(newPinEnc) < 64 or len(newPinEnc) % 16 > 0:
        return CTAP1_ERR_OTHER
    dec = aes(shared_secret, MODE_CBC, bytes(16))
    pin = dec.decrypt(newPinEnc)
    pin_end = pin.find(b'\x00')
    if pin_end == -1:
        return CTAP2_ERR_PIN_POLICY_VIOLATION
    pin = pin[:pin_end]
    if len(pin) < 4:
        return CTAP2_ERR_PIN_POLICY_VIOLATION
    # Authenticator stores LEFT(SHA-256(newPin), 16) on the device,
    # sets the retries counter to 8
    ks_pin.PIN_DIGEST = sha256(pin).digest()[:16]
    ks_pin.PIN = pin
    ks_pin.PIN_RETRIES = ks_pin.PIN_MAX_RETRIES
    ks_pin.save_keystore()
    PIN_CONSECUTIVE_RETRIES = 0
    return CTAP2_OK


def isPINset():
    return ks_pin.PIN != b''


def verifyPIN(pinAuth, clientDataHash):
    n = -(len(ks_pin.PIN_TOKEN)) % 64
    k5c = bytes((c ^ 0x5c for c in ks_pin.PIN_TOKEN)) + b'\x5c' * n
    k36 = bytes((c ^ 0x36 for c in ks_pin.PIN_TOKEN)) + b'\x36' * n
    return hmac_sha256(k5c, k36, clientDataHash)[:16] == pinAuth

from uos import urandom, listdir, mkdir, remove, statvfs
from binascii import hexlify
from cbor import decode, encode
from ecdsa import secp256r1


class KS:
    FN = ''

    def load_keystore(self):
        # cbor-load keystore
        try:
            with open(KS.FN, 'rb') as fin:
                data = fin.read()
        except OSError:
            return False
        try:
            dict_kstore = decode(data)
        except ValueError:
            return False
        if not isinstance(dict_kstore, dict):
            return False
        for k in dict_kstore:
            setattr(self, k, dict_kstore[k])
        return True

    def save_keystore(self):
        # cbor-dump keystore
        dict_kstore = {}
        for m in self.__dict__.keys():
            dict_kstore[m] = getattr(self, m)
        cbor_keystore = encode(dict_kstore)
        with open(KS.FN, 'wb') as fout:
            fout.write(cbor_keystore)


class KS_CTAP2(KS):
    RK_DIR = 'rk_dir'

    def __init__(self):
        KS.FN = "ctap2.keystore"
        if self.load_keystore() is False:
            self.gen_new_ctap2_keys()
            self.save_keystore()

    def gen_new_ctap2_keys(self):
        # hmac keys
        key = urandom(64)
        self.KEY_5C = bytes((k ^ 0x5c for k in key))
        self.KEY_36 = bytes((k ^ 0x36 for k in key))
        # AES key, IV
        self.AES_KEY = urandom(16)
        self.AES_IV = urandom(16)
        # Authenticator Attestation Globally Unique Identifier
        self.AAGUID = urandom(16)
        self.RKS = {}  # list of residential keys, rkids
        self.COUNTER = 0
        try:
            for fn in listdir(KS_CTAP2.RK_DIR):
                remove(KS_CTAP2.RK_DIR + '/' + fn)
        except OSError:
            pass

    def save_rk(self, rkid, user_id, key_handle):
        try:
            stat = statvfs('/flash')
            if stat[0] * stat[3] < 100000:  # bsize * bfree
                # if actual number of free bytes too low exit
                return False
            dir = listdir()
            if KS_CTAP2.RK_DIR not in dir:
                mkdir(KS_CTAP2.RK_DIR)
            dir = listdir(KS_CTAP2.RK_DIR)
            fn = hexlify(user_id).decode('utf-8')
            with open(KS_CTAP2.RK_DIR + '/' + fn, 'wb') as fout:
                fout.write(key_handle)
            if rkid in self.RKS:
                if fn in self.RKS[rkid]:
                    self.RKS[rkid].remove(fn)
                self.RKS[rkid].append(fn)  # most recent ones at the end
            else:
                self.RKS[rkid] = [fn]
            self.save_keystore()
        except OSError:
            return False
        except ValueError:
            return False
        return True

    def load_rk(self, rkid):
        try:
            for fn in self.RKS[rkid]:
                # yield key_handle
                yield open(KS_CTAP2.RK_DIR + '/' + fn, 'rb').read()
        except OSError:
            pass
        except ValueError:
            pass
        except KeyError:
            pass


class KS_PIN(KS):
    def __init__(self):
        KS.FN = "pin.keystore"
        if self.load_keystore() is False:
            self.gen_new_ctap2_pin()
            self.save_keystore()

    def gen_new_ctap2_pin(self):
        # PIN management
        self.PIN = b''
        self.PIN_DIGEST = b''
        self.PIN_TOKEN = b''
        self.PIN_MAX_RETRIES = 8
        self.PIN_RETRIES = self.PIN_MAX_RETRIES
        d, Q = secp256r1.keyGen()
        self.DH_SK = d.to_bytes(32, 'big')
        self.DH_PK_x = Q.x.to_bytes(32, 'big')
        self.DH_PK_y = Q.y.to_bytes(32, 'big')


class KS_U2F(KS):
    def __init__(self):
        KS.FN = "u2f.keystore"
        if self.load_keystore() is False:
            self.gen_new_u2f_keys()
            self.save_keystore()

    def gen_new_u2f_keys(self):
        # hmac keys
        key = urandom(64)
        self.KEY_5C = bytes((k ^ 0x5c for k in key))
        self.KEY_36 = bytes((k ^ 0x36 for k in key))
        # AES key, IV
        self.AES_KEY = urandom(16)
        self.AES_IV = urandom(16)
        self.COUNTER = 0

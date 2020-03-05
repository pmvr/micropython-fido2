from uhashlib import sha256


def hmac_sha256(key_5c, key_36, message):
    # key_5c, key_36 must be 64 bytes (= blocksize)
    h1 = sha256(key_36 + message)
    h2 = sha256(key_5c + h1.digest())
    return h2.digest()

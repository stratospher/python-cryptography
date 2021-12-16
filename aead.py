from poly1305 import Poly1305
from chacha20 import ChaCha20 

# ------------------
# ChaCha20DRBG
# ------------------
def ChaCha20DRBG(key, iv):
    ctr = 0
    while ctr < 2**64:
        yield ChaCha20(key, iv, ctr)
        ctr += 1

# ------------------
# ChaCha20Forward4064DRBG
# ------------------
CHACHA20_KEYLEN = 32 # bytes
CHACHA20_BLOCKSIZE = 64
KEY_ROTATION_INTERVAL = 4064

def ChaCha20Forward4064DRBG(key):
    c20_key = key
    iv = 0
    while True:
        for _ in range(0, KEY_ROTATION_INTERVAL - CHACHA20_BLOCKSIZE, step=CHACHA20_BLOCKSIZE):
            yield from ChaCha20DRBG(c20_key, iv)
        byts = ChaCha20DRBG(c20_key, iv)
        # memory_cleanse(c20_key)
        c20_key = byts[(CHACHA20_BLOCKSIZE - CHACHA20_KEYLEN):]
        iv += 1
        yield byts[:(CHACHA20_BLOCKSIZE - CHACHA20_KEYLEN)]

# ------------------
# ChaCha20Forward4064-Poly1305@Bitcoin cipher suite
# ------------------
HEADER_LEN = 3
MAC_TAGLEN = 16
POLY1305_KEYLEN = 32

# Yields (disconnect, ignore_message, bytes)
def ChaCha20Poly1305AEAD(key_F, key_V, is_encrypt, crypt_bytes, set_ignore=False):
    keystream_F = ChaCha20Forward4064(key_F)
    keystream_V = ChaCha20Forward4064(key_V)
    pos_F = 0
    pos_V = 0

    while True:
        ret = b""
        ignore = False
        disconnect = False

        if is_encrypt and len(crypt_bytes) >= 2**23:
            raise MessageTooLongErr

        # Make sure we have at least 35 bytes in keystream_F
        if pos_F + HEADER_LEN + POLY1305_KEYLEN >= len(keystream_F):
            keystream_F = keystream_F[pos_F:] + ChaCha20Forward4064(key_F)
            pos_F = 0

        # Make sure we have at least len(crypt_bytes) bytes in keystream_V
        if pos_V + len(crypt_bytes) >= len(keystream_V):
            keystream_V = keystream_V[pos_V:] + ChaCha20Forward4064(key_V)
            pos_V = 0

        if is_encrypt:
            header = len(crypt_bytes)
            if set_ignore:
                header = header | (1 << 23)
            ret += htole(header) ^ keystream_F[pos_F:(pos_F + HEADER_LEN)]
        else:
            header = le24toh(crypt_bytes[:HEADER_LEN] ^ keystream_F[:HEADER_LEN])
            ignore = (header & 1<<23 != 0)
            payload_len = header & ~(1<<23)
        pos_F += HEADER_LEN

        poly1305_key = keystream_F[pos_F:(pos_F + POLY1305_KEYLEN)]
        pos_F += POLY1305_KEYLEN

        if is_encrypt:
            ret += (crypt_bytes ^ keystream_V[pos_V:(pos_V + len(crypt_bytes))])
            pos_V += len(crypt_bytes)
            ret += Poly1305(poly1305_key, ret)
        else:
            if timing_safe_cmp(Poly1305(poly1305_key, crypt_bytes[:(HEADER_LEN + payload_len)]), crypt_bytes[(HEADER_LEN + payload_len):]) != 0:
                disconnect = True

            # Decrypt only if authenticated
            if (!disconnect):
                ret += (crypt_bytes ^ keystream_V[pos_V:(pos_V + len(crypt_bytes))])

            # Advance the keystream regardless
            pos_V += len(crypt_bytes)

        yield (disconnect, ignore, ret)
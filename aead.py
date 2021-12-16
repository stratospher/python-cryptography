import sys
from poly1305 import Poly1305
from chacha20 import ChaCha20 

# ------------------
# Helper Functions
# ------------------
def bitwise_xor_le24toh(a, b):
    result_int = int.from_bytes(a, byteorder="little") ^ int.from_bytes(b, byteorder="little")
    return result_int.to_bytes(max(len(a), len(b)), byteorder=sys.byteorder)
        
def bitwise_and(a, b):
    result_int = int.from_bytes(a, byteorder=sys.byteorder) & b
    return result_int

# ------------------
# ChaCha20DRBG
# ------------------
def ChaCha20DRBG(key, iv):
    ctr = 0
    while ctr < 2**64:
        yield ChaCha20(key, iv, ctr).encrypt(bytearray(4096))
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
        for _ in range(0, KEY_ROTATION_INTERVAL - CHACHA20_BLOCKSIZE, CHACHA20_BLOCKSIZE):
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
    keystream_F = next(ChaCha20Forward4064DRBG(key_F))
    keystream_V = next(ChaCha20Forward4064DRBG(key_V))
    pos_F = 0
    pos_V = 0

    while True:
        ret = b""
        ignore = False
        disconnect = False

        if is_encrypt and len(crypt_bytes) >= 2**23:
            raise "MessageTooLongErr"

        # Make sure we have at least 35 bytes in keystream_F
        if pos_F + HEADER_LEN + POLY1305_KEYLEN >= len(keystream_F):
            keystream_F = keystream_F[pos_F:] + next(ChaCha20Forward4064DRBG(key_F))
            pos_F = 0

        # Make sure we have at least len(crypt_bytes) bytes in keystream_V
        if pos_V + len(crypt_bytes) >= len(keystream_V):
            keystream_V = keystream_V[pos_V:] + next(ChaCha20Forward4064DRBG(key_V))
            pos_V = 0

        if is_encrypt:
            header = len(crypt_bytes)
            if set_ignore:
                header = header | (1 << 23)
            ret += bytes([aa ^ bb for aa, bb in zip(header.to_bytes(3, byteorder="little"), keystream_F[pos_F:(pos_F + HEADER_LEN)])])
        else:
            header = bitwise_xor_le24toh(crypt_bytes[:HEADER_LEN], keystream_F[:HEADER_LEN])
            ignore = bitwise_and(header, 1<<23) != 0
            payload_len = bitwise_and(header, ~(1<<23))
        pos_F += HEADER_LEN

        poly1305_key = keystream_F[pos_F:(pos_F + POLY1305_KEYLEN)]
        pos_F += POLY1305_KEYLEN

        if is_encrypt:
            ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes, keystream_V[pos_V:(pos_V + len(crypt_bytes))])])
            pos_V += len(crypt_bytes)
            ret += Poly1305(poly1305_key).create_tag(ret)
        else:
            if (Poly1305(poly1305_key).create_tag(crypt_bytes[:(HEADER_LEN + payload_len)]) != crypt_bytes[(HEADER_LEN + payload_len):]):
                disconnect = True

            # Decrypt only if authenticated
            if (not disconnect):
                PLAIN_LEN = len(crypt_bytes) - HEADER_LEN - MAC_TAGLEN
                ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[HEADER_LEN:HEADER_LEN+PLAIN_LEN], keystream_V[pos_V:(pos_V + PLAIN_LEN)])])

            # Advance the keystream regardless
            pos_V += PLAIN_LEN

        yield disconnect, ignore, ret

def TestAEAD(plaintext, k_F, k_V, ciphertext_with_mac):
    plaintext = bytearray.fromhex(plaintext)
    k_F = bytearray.fromhex(k_F)
    k_V = bytearray.fromhex(k_V)
    ciphertext_with_mac = bytearray.fromhex(ciphertext_with_mac)

    global countYay
    global countMeh

    # Test Encryption
    for _, _, ret in ChaCha20Poly1305AEAD(k_F, k_V, True, plaintext):
        if(ret == ciphertext_with_mac):
            countYay += 1
        else:
            countMeh += 1
        break

    # Test Decryption
    for _, _, ret in ChaCha20Poly1305AEAD(k_F, k_V, False, ciphertext_with_mac):
        if(ret == plaintext):
            countYay += 1
        else:
            countMeh += 1
        break

countYay = 0
countMeh = 0

TestAEAD("0000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "6bb8e076b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8babf71de83e6e27c82490bdc8615d0c9e"
        )
# TestAEAD("0000000000000000000000000000000000000000000000000000000000",
#         "0000000000000000000000000000000000000000000000000000000000000000",
#         "0000000000000000000000000000000000000000000000000000000000000000",
#         "77b8e076b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8bfb6cf9dcd7e2ee807d5ff981eb4a135a"
#         )
TestAEAD("f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9",
        "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "3a40c1c868cd145bd54691e9b6b402c78bd7ea9c3724fc50dfc69a4a96be8dec4e70e958188aa69222eaef3f47f8003f1bc13dcf9e661be8e1b671e9cf46ba705bca963e0477a5b3c2e2c66feb8207269ddb01b1372aad68563bb4aad135afb06fbe40b310b63bef578ff939f3a00a6da9e744d28ba070294e5746d2ca7bb8ac2c8e3a855ab4c9bcd0d5855e11b52cacaa2ddb34c0a26cd04f4bc10de6dc151d4ee7ced2c2b0de8ded33ff11f301e4027559e8938b69bceb1e5e259d4122056f6adbd48a0628b912f90d72838f2f3aaf6b88342cf5bac3cb688a9b0f7afc73a7e3cad8e71254c786ea000240ae7bd1df8bcfca07f3b885723a9d7f89736461917bb2791faffbe34650c8501daaef76"
        )

print(countYay, "passed and", countMeh, "failed")
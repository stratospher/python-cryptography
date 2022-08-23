#!/usr/bin/env python3
"""Python implementation of RFC 8439
"""

import struct
import sys

from poly1305 import Poly1305
from newchacha20 import ChaCha20

# Helper Functions
def bitwise_xor_le24toh(a, b):
    result_int = int.from_bytes(a, byteorder="little") ^ int.from_bytes(b, byteorder="little")
    return result_int.to_bytes(max(len(a), len(b)), byteorder=sys.byteorder)

def bitwise_and(a, b):
    result_int = int.from_bytes(a, byteorder=sys.byteorder) & b
    return result_int

def pad16(x):
    if len(x) % 16 == 0:
        return b''
    return b'\x00' * (16 - (len(x) % 16))

# ChaCha20DRBG
def ChaCha20DRBG(key, iv):
    ctr = 0
    while ctr < 2**32:
        yield ChaCha20(key, iv, ctr).keystream_bytes
        ctr += 1

def get_nonce(rekey_ctr, msg_ctr):
    return msg_ctr.to_bytes(4, 'little') + rekey_ctr.to_bytes(8, 'little')

# AEAD Construction from RFC 8439
def rfc8439_crypt_and_auth(key, nonce, is_encrypt, crypt_bytes, aad=b""):
    otk = Poly1305.poly1305_key_gen(key, nonce)
    mac_this_payload = crypt_bytes
    if is_encrypt:
        ciphertext = ChaCha20(key, nonce, 1).encrypt(crypt_bytes)
        mac_this_payload = ciphertext
    else:
        plaintext = ChaCha20(key, nonce, 1).encrypt(crypt_bytes)
    mac_data = aad + pad16(aad)
    mac_data += mac_this_payload + pad16(mac_this_payload)
    mac_data += struct.pack('<Q', len(aad))
    mac_data += struct.pack('<Q', len(mac_this_payload))
    tag = Poly1305(otk).create_tag(mac_data)
    if is_encrypt:
        return ciphertext, tag
    else:
        return plaintext, tag

# def rfc8439_auth_and_decrypt(key, nonce, crypt_bytes, mac_tag, aad=b""):
#     plaintext, computed_mac_tag = rfc8439_crypt_and_auth(key, nonce, False, crypt_bytes, aad)
#     if mac_tag != computed_mac_tag:


CHACHA20_BLOCKSIZE = 64 # bytes
REKEY_INTERVAL = 256 # messages

def TestRFC8439(hex_aad, hex_key, hex_nonce, hex_plaintext, hex_expected_ciphertext, hex_expected_auth_tag):
    aad = bytearray.fromhex(hex_aad)
    key = bytearray.fromhex(hex_key)
    nonce = bytearray.fromhex(hex_nonce)
    plaintext = bytearray.fromhex(hex_plaintext)

    ciphertext, mac_tag = rfc8439_crypt_and_auth(key, nonce, True, plaintext, aad)
    assert hex_expected_ciphertext == ciphertext.hex()
    assert hex_expected_auth_tag == mac_tag.hex()

    # todo: make it more fancy - and give automatic success checking
    plaintext, computed_mac_tag = rfc8439_crypt_and_auth(key, nonce, False, ciphertext, aad)
    assert computed_mac_tag.hex() == mac_tag.hex()
    assert hex_plaintext == plaintext.hex()

TestRFC8439("50515253c0c1c2c3c4c5c6c7",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "070000004041424344454647",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691")

TestRFC8439("f33388860000000000004e91",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "000000000102030405060708",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b",
            "eead9d67890cbb22392336fea1851f38")
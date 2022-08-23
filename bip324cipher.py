#!/usr/bin/env python3
"""Python implementation of BIP 324 Cipher suite
Details: https://github.com/bitcoin/bitcoin/pull/25361
"""

import hashlib
from newchacha20 import FSChaCha20
from rfc8439 import get_nonce, rfc8439_crypt_and_auth

LENGTH_FIELD_LEN = 3
HEADER_LEN = 1
RFC8439_TAG_LEN = 16
IGNORE_BIT_POS = 7
REKEY_INTERVAL = 256

class BIP324CipherSuite:
    def __init__(self, key_L, key_P, rekey_salt):
        self.L = FSChaCha20(key_L, rekey_salt, REKEY_INTERVAL)
        self.key_P = key_P
        self.rekey_ctr = 0
        self.msg_ctr = 0
        self.rekey_salt = rekey_salt

    # todo:
    # def decrypt_length(self, crypt_bytes):
    #     pass

    def crypt(self, is_encrypt, crypt_bytes, set_ignore=False):
        nonce = get_nonce(self.rekey_ctr, self.msg_ctr)
        ret = b""
        ignore = False
        disconnect = False

        if is_encrypt:
            if len(crypt_bytes) >= 2**24:
                raise "MessageTooLongErr"
            payload_len = HEADER_LEN + len(crypt_bytes)
            header = 1 << IGNORE_BIT_POS if set_ignore else 0
            ciphertext, mac_tag = rfc8439_crypt_and_auth(self.key_P, nonce, True, header.to_bytes(HEADER_LEN, 'big') + crypt_bytes)
            ret += self.L.encipher(payload_len.to_bytes(LENGTH_FIELD_LEN, 'little')) + ciphertext + mac_tag
        else:
            payload_len = int.from_bytes(self.L.encipher(crypt_bytes[:LENGTH_FIELD_LEN]), 'little')
            mac_tag = crypt_bytes[LENGTH_FIELD_LEN + payload_len: LENGTH_FIELD_LEN + payload_len + RFC8439_TAG_LEN]
            plaintext, computed_mac_tag = rfc8439_crypt_and_auth(self.key_P, nonce, False, crypt_bytes[LENGTH_FIELD_LEN:LENGTH_FIELD_LEN + payload_len])
            # Terminate connection if authentication fails
            if mac_tag != computed_mac_tag:
                disconnect = True
            else:
                assert len(crypt_bytes) == LENGTH_FIELD_LEN + payload_len + RFC8439_TAG_LEN
                header = int.from_bytes(plaintext[:HEADER_LEN], 'big')
                ignore = header >> IGNORE_BIT_POS
                if not ignore:
                    ret += plaintext[HEADER_LEN:]

        self.msg_ctr += 1
        if self.msg_ctr == REKEY_INTERVAL:
            # todo: remove double hash
            self.key_P = hashlib.sha256(self.rekey_salt + self.key_P).digest()
            self.msg_ctr = 0
            self.rekey_ctr += 1

        return disconnect, ignore, ret

def TestBIP324CipherSuite(hex_input, hex_key_l, hex_key_p, hex_rekey_salt, hex_expected_output_seq_0, hex_expected_output_seq_999):
    plaintext = bytearray.fromhex(hex_input)
    key_l = bytearray.fromhex(hex_key_l)
    key_p = bytearray.fromhex(hex_key_p)
    rekey_salt = bytearray.fromhex(hex_rekey_salt)
    suite_enc = BIP324CipherSuite(key_l, key_p, rekey_salt)
    suite_dec = BIP324CipherSuite(key_l, key_p, rekey_salt)
    for i in range(1000):
        _, _, ret = suite_enc.crypt(True, plaintext)
        if i == 0:
            assert ret.hex() == hex_expected_output_seq_0
        elif i == 999:
            assert ret.hex() == hex_expected_output_seq_999
        _, _, new_plaintext = suite_dec.crypt(False, ret)
        assert new_plaintext == plaintext

TestBIP324CipherSuite("",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "77b8e09fbedcfd1809ff3c10adf8277fcc0581b8",
                      "8e6aedd9148bd3bafc2377f8e4f6559b4ec26ff4")

TestBIP324CipherSuite("0000000000000000000000000000000000000000000000000000000000000000",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "57b8e09f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29e7e38bb44c94b6a43c525ffca66c79e9",
                      "ae6aedd99d957e0f9719d248a1f25357573c4eb7fbf047911fd530bb2ec6cf6d921743a3d16ee9c81e352ba0a29a3c1c7dec8b6b")

TestBIP324CipherSuite("0100000000000000000000000000000000000000000000000000000000000000",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "0000000000000000000000000000000000000000000000000000000000000000",
                      "57b8e09f06e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed2929449b86c1e4e213676824f2c48e5336",
                      "ae6aedd99c957e0f9719d248a1f25357573c4eb7fbf047911fd530bb2ec6cf6d921743a3fced1d140e9f3a4103e5c5e687cb2938")

TestBIP324CipherSuite("fc0000f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9",
                      "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                      "6f5ef19ed6f1a5e2db2b119494f21d8c2de638a4c6ec3b5b4d43f3196152ea10",
                      "c641c1184442315c7340b89171039acb48f95287e66e56f7afa7cf00f95044d26fb69d46ac5c16a2d57a1cadc39160644717559e73480734410a3f543c5f231a7d7ed77af2a64681f6a7417283cef85504ac5de9fdea100e6c67ef7a1bfcd888a92a5f1ef2c9074b44b572aa748f29ff61a850ce40470004dff5cc1d926c5abe25ace47a12c5373094a26bab027e008154fb630aa062490b5421e96691a3f79557f7a79e3cfd9100796671ea241703ddf326f113adf1694bbd6e0ca032e16f936e7bfbf174e7ef4af5b53a6a9102e6fa41a8e589290f39a7bc7a6003088c612a43a36c2e9f2e740797ad3a2a1a80e0f67157fb9abc40487077368e94751a266a0b2dac24f0adabd5c6d7ba54316eee951da560",
                      "7e3f8da87ddd62416fa860e3dcc8a999385425c07809de3b763e82545549d93f43a4cdb01b20e1049f68f31b13728fdf60fd8d65099ecc65d7fd90925733b7372057fa2174e487228fbb34e487a16342b721035f7f7ef26b962140aba9ba1a1a31e6bbacdfb406017f97449d3a6996b3266306bde62db2af8a3523ac5c65181b9b1818d1266a8d15ffb80675f84369411ab2bac744316180fbe08aa635dddc9dcaac7e249241665029b3ccae3b996840020dd46ce83e97a399568dcf1f58a8e29ee2535f5801ee006767218c01b31834e9ad0cf2cfd32321b16bd009233ea6a1896fbe2f6ebc2a6edfb8fcef6e4b90326b53b657f663f1f741f7f790abc2d97a1d57a3d3c2e024f783fe01dd00bad7254a1a21")

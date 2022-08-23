#!/usr/bin/env python3
"""
ChaCha20 implementation with 256 bit key and 96 bit nonce
which doesn't waste pseudorandom bytes
"""

import hashlib
CHACHA20_BLOCKSIZE = 64 # bytes

def word(x):
    return x & 0xffffffff

def xor(a, b):
    return b''.join([bytes([x ^ y]) for x, y in zip(a, b)])

def rotate(x, n):
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)

def bytes_to_words(b):
    return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]

def words_to_bytes(w):
    return b''.join([i.to_bytes(4, 'little') for i in w])

class ChaCha20:
    _round_mixup_box = [(0, 4, 8, 12),
                        (1, 5, 9, 13),
                        (2, 6, 10, 14),
                        (3, 7, 11, 15),
                        (0, 5, 10, 15),
                        (1, 6, 11, 12),
                        (2, 7, 8, 13),
                        (3, 4, 9, 14)]

    def __init__(self, key, nonce, counter=0):
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")
        self._key = key
        self._nonce = nonce
        self._counter = counter
        self.keystream_bytes = b""
        self._setup_state(key, nonce)

    def _inner_block(self, state):
        for a, b, c, d in ChaCha20._round_mixup_box:
            self._quarter_round(state, a, b, c, d)

    def _quarter_round(self, x, a, b, c, d):
        x[a] = word(x[a] + x[b]); x[d] ^= x[a]; x[d] = rotate(x[d], 16)
        x[c] = word(x[c] + x[d]); x[b] ^= x[c]; x[b] = rotate(x[b], 12)
        x[a] = word(x[a] + x[b]); x[d] ^= x[a]; x[d] = rotate(x[d], 8)
        x[c] = word(x[c] + x[d]); x[b] ^= x[c]; x[b] = rotate(x[b], 7)

    def _setup_state(self, key, iv):
        self._state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        self._state.extend(bytes_to_words(key))
        self._state.append(self._counter)
        self._state.extend(bytes_to_words(iv))
    
    def keystream(self):
        state = self._state[:]
        for j in range(10):
            self._inner_block(state)
        state = [(st + wrkSt) & 0xffffffff for st, wrkSt in zip(state, self._state)]
        self._counter += 1
        return words_to_bytes(state)

    def encrypt(self, m):
        c = b''
        for i in range(0, len(m), 64):
            self._setup_state(self._key, self._nonce)
            self.keystream_bytes += self.keystream()
        c += xor(m, self.keystream_bytes[:len(m)])
        self.keystream_bytes = self.keystream_bytes[len(m):]
        return c

def TestChaCha20(hex_key, nonce, counter, hex_expected_keystream, hex_input, hex_expected_output):
    key = bytearray.fromhex(hex_key)
    nonce = bytearray.fromhex(nonce)
    
    if hex_expected_keystream:
        c = ChaCha20(key, nonce, counter)
        computed_keystream = c.keystream().hex()
        assert computed_keystream[:len(hex_expected_keystream)] == hex_expected_keystream

    if hex_input:
        assert len(hex_input) == len(hex_expected_output)
        c = ChaCha20(key, nonce, counter)
        input = bytearray.fromhex(hex_input)
        output = c.encrypt(input).hex()
        assert output == hex_expected_output

# Test vector from RFC 8439
# test encryption
rfc8439_nonce0 = "000000000000000000000000"
rfc8439_nonce1 = "000000000000004a00000000"
rfc8439_nonce2 = "000000000000000000000002"

TestChaCha20("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             rfc8439_nonce1,
             1,
             "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b7",
             "",
             "")

TestChaCha20("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             rfc8439_nonce1,
             2,
             "69a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945398b6eda1a832c89c167eacd901d7e2bf363740373201aa188fbbce83991c4ed",
             "",
             "")

TestChaCha20("0000000000000000000000000000000000000000000000000000000000000000",
             rfc8439_nonce0,
             0,
             "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
             "",
             "")

TestChaCha20("0000000000000000000000000000000000000000000000000000000000000000",
             rfc8439_nonce0,
             1,
             "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
             "",
             "")

TestChaCha20("0000000000000000000000000000000000000000000000000000000000000001",
             rfc8439_nonce0,
             1,
             "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
             "",
             "")

TestChaCha20("00ff000000000000000000000000000000000000000000000000000000000000",
             rfc8439_nonce0,
             2,
             "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
             "",
             "")

TestChaCha20("0000000000000000000000000000000000000000000000000000000000000000",
             rfc8439_nonce2,
             0,
             "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
             "",
             "")

TestChaCha20("0000000000000000000000000000000000000000000000000000000000000000",
             rfc8439_nonce0,
             0,
             "",
             "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
             "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")

TestChaCha20("0000000000000000000000000000000000000000000000000000000000000001",
             rfc8439_nonce2,
             1,
             "",
             "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f", "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221")

TestChaCha20("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
             rfc8439_nonce2,
             42,
             "",
             "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
             "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1")

TestChaCha20("0000000000000000000000000000000000000000000000000000000000000000",
             rfc8439_nonce0,
             0,
             "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
             "",
             "")

TestChaCha20("0000000000000000000000000000000000000000000000000000000000000001",
             rfc8439_nonce2,
             0,
             "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739",
             "",
             "")

TestChaCha20("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
             rfc8439_nonce2,
             0,
             "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae",
             "",
             "")

# ChaCha20DRBG
def ChaCha20DRBG(key, iv):
    ctr = 0
    while ctr < 2**32:
        yield ChaCha20(key, iv, ctr).keystream()
        ctr += 1

def get_nonce(rekey_ctr, msg_ctr):
    return msg_ctr.to_bytes(4, 'little') + rekey_ctr.to_bytes(8, 'little')

class FSChaCha20:
    def __init__(self, key, rekey_salt, rekey_interval):
        self.key = key
        self.rekey_ctr = 0 # internal 64-bit re-key counter
        self.msg_ctr = 0
        self.keystream = b""
        self.rekey_salt = rekey_salt
        self.rekey_interval = rekey_interval
        self.drbg_generator = ChaCha20DRBG(self.key, get_nonce(self.rekey_ctr, 0))

    def encipher(self, input):
        # We do not use the message counter in the nonce to reduce wasted pseudorandom bytes in the outer layer
        if len(self.keystream) < len(input):
            for _ in range(((len(input) - 1) // CHACHA20_BLOCKSIZE) + 1):
                self.keystream += next(self.drbg_generator)
        output = xor(input, self.keystream[:len(input)])
        self.keystream = self.keystream[len(input):]

        self.msg_ctr += 1
        if self.msg_ctr == self.rekey_interval:
            self.rekey_ctr += 1
            self.msg_ctr = 0
            self.key = hashlib.sha256(self.rekey_salt + self.key).digest()
            self.drbg_generator = ChaCha20DRBG(self.key, get_nonce(self.rekey_ctr, 0))
            self.keystream = b""

        return output

def TestFSChaCha20(hex_plaintext, hex_key, hex_rekey_salt, rekey_interval, ciphertext_after_rotation):
    key = bytearray.fromhex(hex_key)
    assert len(key) == 32
    salt = bytearray.fromhex(hex_rekey_salt)
    assert len(salt) == 32
    plaintext = bytearray.fromhex(hex_plaintext)
    rekey_salt = bytearray.fromhex(hex_rekey_salt)

    fsc20 = FSChaCha20(key, salt, rekey_interval)
    c20 = ChaCha20(key, bytearray.fromhex(rfc8439_nonce0))

    for i in range(rekey_interval):
        fsc20_output = fsc20.encipher(plaintext)
        c20_output = c20.encrypt(plaintext)
        assert fsc20_output == c20_output
    
    # At the rotation interval, the outputs will no longer match
    fsc20_output = fsc20.encipher(plaintext)
    c20_output = c20.encrypt(plaintext)
    assert fsc20_output != c20_output

    new_key = hashlib.sha256(rekey_salt + key).digest()
    c20 = ChaCha20(new_key, bytearray.fromhex("000000000100000000000000"))
    c20_output = c20.encrypt(plaintext)
    assert c20_output == fsc20_output
    assert fsc20_output.hex() == ciphertext_after_rotation

TestFSChaCha20("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
               "0000000000000000000000000000000000000000000000000000000000000000",
               "0000000000000000000000000000000000000000000000000000000000000000",
               256,
               "65bd1a6644c605995d3e0663d1500e761ebfe174475ee6148ae92b243294c042")

TestFSChaCha20("01",
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
               "0000000000000000000000000000000000000000000000000000000000000000",
                5,
                "17")

TestFSChaCha20("e93fdb5c762804b9a706816aca31e35b11d2aa3080108ef46a5b1f1508819c0a",
               "8ec4c3ccdaea336bdeb245636970be01266509b33f3d2642504eaf412206207a",
               "8bb571662db12d38ee4e2630d4434f6f626cb0e6007e3cc41d2f44dbb32e6e9d",
               4096,
               "03988d3808ca6b0f98e2ae6d9d80a65ceb5a799e5bbaf5d161885b4c4cc18118")

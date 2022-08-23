#!/usr/bin/env python3
"""Test-only Elligator Swift implementation

WARNING: This code is slow and uses bad randomness.
Do not use for anything but tests."""

import os
import hashlib
import random
import unittest

from key import fe, ECKey, ECPubKey, SECP256K1, SECP256K1_G, SECP256K1_ORDER

C1 = fe(-3).sqrt()
C2 = -(C1 - fe(1)) / fe(2)
B = fe(7)

def forward_map(u, t):
    """Forward mapping function

    Parameters:
        fe, fe : any field element
    Returns:
        fe : X coordinate of a point on the secp256k1 curve
    """
    if u == fe(0):
        u = fe(1)
    if t == fe(0):
        t = fe(1)
    if u**3 + t**2 + B == fe(0):# todo: maybe comment in PR
        t *= fe(2)
    p = u**3 + t**2 + B
    m = u**3 - t**2 + B
    v = (C1*m/p - fe(1)) * u/fe(2)
    w = p/(C1*t*u)
    x1 = v
    x2 = -u-v
    x3 = u+w**2
    for x in [x3, x2, x1]:
        g1 = x**3 + B
        if g1.is_square():
            return x

def reverse_map(x, u, i):
    """Reverse mapping function

    Parameters:
        fe, fe : x is X coordinate of a point, u is a random fe
        i      : integer in range [0,7]
    Returns:
        t (of type fe) : such that forward_map(u, t) = x or None
    """
    g = u**3 + B
    if i&2 == 0:
        o = -(x+u)**3+B
        if o.is_square():
            return None
        if i&1:
            x = -(x+u)
        w = g/(u*x-(x+u)**2)
    else:
        w = x-u
        if w == fe(0):
            return None
        r = -w*(fe(3)*u**2*w+fe(4)*g)
        r = r.sqrt()
        if r.val is None:
            return None
        if i&1:
            if r == fe(0):
                return None
            r = -r
        x = -(r/w+u)/fe(2)
    w = w.sqrt()
    if w.val is None:
        return None
    if i&4:
        w = -w
    u = u*C2 + x
    t = w*u
    return t

def encode(P, hasher):
    cnt = 0
    while True:
        if cnt % 64 == 0:
            hash = hasher.copy()
            hash.update(cnt.to_bytes(4, 'little'))
            cnt += 1
            branch_hash = hash.digest()

        j = (branch_hash[(64-cnt) % 64 >> 1] >> (((64-cnt) % 64 & 1) << 2)) & 7
        hash = hasher.copy()
        hash.update(cnt.to_bytes(4, 'little'))
        cnt += 1
        u = fe(int.from_bytes(hash.digest(), 'big'))
        if u == fe(0):
            continue
        t = reverse_map(P[0], u, j)
        if t is None:
            continue
        if t.is_odd() != P[1].is_odd():
            t = -t
        return u.to_bytes() + t.to_bytes()

def ellswift_create(privkey, rnd32=bytearray(32)):
    # secret key -> 64 bytes encoding
    m = hashlib.sha256()
    m.update(b"secp256k1_ellswift_create")
    m.update(bytearray(7))
    m.update(privkey.get_bytes())
    m.update(rnd32)
    m.update(bytearray(19))
    pubkey = privkey.get_pubkey()
    ge = pubkey.get_group_element()
    return encode(ge, m)

def ellswift_encode(pubkey, randombytes):
    """
    generates elligator swift encoding of pubkey
    Parameters:
        pubkey : ECPubKey object
        randombytes : 32 bytes entropy
    Returns: 64 bytes encoding
    """
    ge = pubkey.get_group_element()
    hasher = hashlib.sha256()
    hasher.update(b"secp256k1_ellswift_encode")
    hasher.update(bytearray(25))
    hasher.update(randombytes)
    hasher.update(ge[0].val.to_bytes(32, 'big'))
    hasher.update((ge[1].val & 1).to_bytes(1, 'big'))
    return encode(ge, hasher)

def ellswift_decode(enc):
    """
     decodes elligator swift encoding to obtain pubkey
     Parameters:
         enc : 64 bytes encoding
     Returns: ECPubKey object
     """
    u, v = fe.from_bytes(enc[:32]), fe.from_bytes(enc[32:])
    x = forward_map(u, v)
    if v.val % 2 == 0:
        compressed_sec = b'\x02' + x.val.to_bytes(32, 'big')
    else:
        compressed_sec = b'\x03' + x.val.to_bytes(32, 'big')
    pubkey = ECPubKey()
    pubkey.set(compressed_sec)
    return pubkey

def xdh_hash(x, ours64, theirs64):
    m = hashlib.sha256()
    if ours64 <= theirs64:
        m.update(ours64)
        m.update(theirs64)
    else:
        m.update(theirs64)
        m.update(ours64)
    m.update(x)
    return m.digest()

def ellswift_xdh(theirs64, ours64, secretkey):
    their_pubkey = ellswift_decode(theirs64)
    their_pubkey = their_pubkey.get_group_element()
    their_pubkey = (their_pubkey[0].val, their_pubkey[1].val, 1)
    our_privkey = int.from_bytes(secretkey.get_bytes(), "big")
    x, y, _ = SECP256K1.affine(SECP256K1.mul([(their_pubkey, our_privkey)]))
    return xdh_hash(x.to_bytes(32, 'big'), ours64, theirs64)

def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")

class TestFrameworkEllSwift(unittest.TestCase):
    def test_encode_decode(self):
        for i in range(100):
            m = random.randrange(1, SECP256K1_ORDER)
            curve_point = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, m)]))
            pubkey1 = ECPubKey()
            pubkey1.set_from_curve_point(curve_point)
            rnd32 = os.urandom(32)
            encoding = ellswift_encode(pubkey1, rnd32)
            pubkey2 = ellswift_decode(encoding)
            assert pubkey1.get_bytes() == pubkey2.get_bytes()

    def test_create_decode(self):
        for i in range(100):
            privkey = ECKey()
            privkey.generate()
            pubkey1 = privkey.get_pubkey()
            rnd32 = os.urandom(32)
            encoding = ellswift_create(privkey, rnd32)
            pubkey2 = ellswift_decode(encoding)
            assert pubkey1.get_bytes() == pubkey2.get_bytes()

    def test_ellswift_xdh(self):
        for i in range(100):
            randombytes1 = os.urandom(32)
            randombytes2 = os.urandom(32)
            privkey1 = ECKey()
            privkey1.generate()
            privkey2 = ECKey()
            privkey2.generate()
            encoding1 = ellswift_create(privkey1, randombytes1)
            encoding2 = ellswift_create(privkey2, randombytes2)
            shared_secret1 = ellswift_xdh(encoding1, encoding2, privkey2)
            shared_secret2 = ellswift_xdh(encoding2, encoding1, privkey1)
            assert shared_secret1 == shared_secret2
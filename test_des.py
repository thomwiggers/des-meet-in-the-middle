#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from binascii import unhexlify
from random import randint

import des


class TestDes(unittest.TestCase):

    _test_vectors = map(lambda x: map(unhexlify, x), (
        # key                plain               ciphertext
        ('133457799BBCDFF1', '0123456789abcdef', '85E813540F0AB405'),
        ('752878397493CB70', '1122334455667788', 'B5219EE81AA7499D'),
        ('752878397493CB70', '99AABBCCDDEEFF00', '2196687E13973856'),
        ('0101010101010102', '0102030405060708', '6613fc98d6d2f56b')
    ))

    def test_encrypt(self):
        for key, plain, cipher in self._test_vectors:
            self.assertEqual(des.encrypt(key, plain), cipher)

    def test_decrypt(self):
        for key, plain, cipher in self._test_vectors:
            self.assertEqual(des.decrypt(key, cipher), plain)

    def test_nth_key(self):
        self.assertEqual(des.nth_key(765637), unhexlify('01010101015dba8a'))
        self.assertEqual(des.encrypt(des.nth_key(1),
                                     unhexlify('0102030405060708')),
                         unhexlify('6613fc98d6d2f56b'))

        for j in range(1000):
            key = des.nth_key(randint(0, 10000000))
            for i in range(8):
                # Assert hamming weight odd for each byte
                self.assertEqual(bin(key[i]).count('1') % 2, 1)

    def test_meet_in_the_middle(self):
        bits = 8
        key1 = des.nth_key(randint(0, 2**bits))
        key2 = des.nth_key(randint(0, 2**bits))

        pairs = []
        for i in range(3):
            plain_text = bytes((randint(0, 255) for i in range(8)))
            cipher_text = des.encrypt(key2, des.encrypt(key1, plain_text))
            pairs.append((plain_text, cipher_text))

        self.assertEqual(des.meet_in_the_middle(bits, pairs), (key1, key2))


if __name__ == '__main__':
    unittest.main()

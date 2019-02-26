import pre
import unittest

class TestGenerationMethods(unittest.TestCase):
    def test_generate_key(self):
        self.assertIsNotNone(pre.generate_key())
        self.assertNotEqual(pre.generate_key(), pre.generate_key())

    def test_generate_token(self):
        alice = pre.generate_key()
        self.assertIsNotNone(alice)
        bob = pre.generate_key()
        self.assertIsNotNone(bob)

        token1 = pre.generate_token(alice, bob)
        self.assertIsNotNone(token1)
        token2 = pre.generate_token(alice, bob)
        self.assertIsNotNone(token2)
        token3 = pre.generate_token(bob, alice)
        self.assertIsNotNone(token3)

        self.assertEqual(token1, token2)
        self.assertNotEqual(token1, token3)

    def test_generate_msg(self):
        msg1 = pre.generate_key()
        self.assertIsNotNone(msg1)
        msg2 = pre.generate_key()
        self.assertIsNotNone(msg2)
        self.assertNotEqual(msg1, msg2)

class TestEncryptionDecryption(unittest.TestCase):
    def test_encrypt(self):
        alice = pre.generate_key()
        bob = pre.generate_key()
        msg1 = pre.generate_msg()
        msg2 = pre.generate_msg()

        self.assertIsNotNone(pre.encrypt(alice, msg1))
        self.assertNotEqual(pre.encrypt(alice, msg1), pre.encrypt(alice, msg1))
        self.assertNotEqual(pre.encrypt(alice, msg1), pre.encrypt(bob, msg1))
        self.assertNotEqual(pre.encrypt(alice, msg1), pre.encrypt(alice, msg2))

    def test_encrypt_decrypt(self):
        alice = pre.generate_key()
        bob = pre.generate_key()
        msg = pre.generate_msg()

        cipher = pre.encrypt(alice, msg)
        self.assertIsNotNone(cipher)
        self.assertEqual(msg, pre.decrypt(alice, cipher))
        self.assertNotEqual(msg, pre.decrypt(bob, cipher))

class TestReEncryption(unittest.TestCase):
    def test_re_encrypt(self):
        alice = pre.generate_key()
        bob = pre.generate_key()
        msg1 = pre.generate_msg()
        msg2 = pre.generate_msg()
        msg3 = pre.generate_msg()

        cipher1 = pre.encrypt(alice, msg1)
        self.assertIsNotNone(cipher1)
        self.assertEqual(msg1, pre.decrypt(alice, cipher1))
        self.assertNotEqual(msg1, pre.decrypt(bob, cipher1))

        token = pre.generate_token(alice, bob)
        re_cipher1 = pre.apply_token(token, cipher1)
        self.assertEqual(msg1, pre.decrypt(bob, re_cipher1))
        self.assertNotEqual(msg1, pre.decrypt(alice, re_cipher1))

        cipher2 = pre.encrypt(alice, msg2)
        re_cipher2 = pre.apply_token(token, cipher2)
        self.assertEqual(msg2, pre.decrypt(bob, re_cipher2))
        self.assertNotEqual(msg2, pre.decrypt(alice, re_cipher2))

        cipher3 = pre.encrypt(bob, msg3)
        re_cipher3 = pre.apply_token(token, cipher3)
        self.assertNotEqual(msg3, pre.decrypt(bob, re_cipher3))
        self.assertNotEqual(msg3, pre.decrypt(alice, re_cipher3))

class TestMessageConversion(unittest.TestCase):
    def test_msg_to_ints(self):
        msg1 = pre.generate_msg()
        ints1 = pre.msg_to_ints(msg1)
        self.assertIsNotNone(ints1)
        self.assertEqual(ints1, pre.msg_to_ints(msg1))

        msg2 = pre.generate_msg()
        ints2 = pre.msg_to_ints(msg2)
        self.assertIsNotNone(ints2)
        self.assertEqual(ints2, pre.msg_to_ints(msg2))

        self.assertNotEqual(ints1, ints2)

if __name__ == '__main__':
    unittest.main()

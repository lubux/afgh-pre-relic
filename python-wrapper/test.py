import pypre
import unittest

class TestGenerationMethods(unittest.TestCase):
    def test_generate_key(self):
        self.assertIsNotNone(pypre.generate_key())
        self.assertNotEqual(pypre.generate_key(), pypre.generate_key())

    def test_generate_token(self):
        alice = pypre.generate_key()
        self.assertIsNotNone(alice)
        bob = pypre.generate_key()
        self.assertIsNotNone(bob)

        token1 = pypre.generate_token(alice, bob)
        self.assertIsNotNone(token1)
        token2 = pypre.generate_token(alice, bob)
        self.assertIsNotNone(token2)
        token3 = pypre.generate_token(bob, alice)
        self.assertIsNotNone(token3)

        self.assertEqual(token1, token2)
        self.assertNotEqual(token1, token3)

    def test_generate_msg(self):
        msg1 = pypre.generate_key()
        self.assertIsNotNone(msg1)
        msg2 = pypre.generate_key()
        self.assertIsNotNone(msg2)
        self.assertNotEqual(msg1, msg2)

class TestEncryptionDecryption(unittest.TestCase):
    def test_encrypt(self):
        alice = pypre.generate_key()
        bob = pypre.generate_key()
        msg1 = pypre.generate_msg()
        msg2 = pypre.generate_msg()

        self.assertIsNotNone(pypre.encrypt(alice, msg1))
        self.assertNotEqual(pypre.encrypt(alice, msg1), pypre.encrypt(alice, msg1))
        self.assertNotEqual(pypre.encrypt(alice, msg1), pypre.encrypt(bob, msg1))
        self.assertNotEqual(pypre.encrypt(alice, msg1), pypre.encrypt(alice, msg2))

    def test_encrypt_decrypt(self):
        alice = pypre.generate_key()
        bob = pypre.generate_key()
        msg = pypre.generate_msg()

        cipher = pypre.encrypt(alice, msg)
        self.assertIsNotNone(cipher)
        self.assertEqual(msg, pypre.decrypt(alice, cipher))
        self.assertNotEqual(msg, pypre.decrypt(bob, cipher))

class TestReEncryption(unittest.TestCase):
    def test_re_encrypt(self):
        alice = pypre.generate_key()
        bob = pypre.generate_key()
        msg1 = pypre.generate_msg()
        msg2 = pypre.generate_msg()
        msg3 = pypre.generate_msg()

        cipher1 = pypre.encrypt(alice, msg1)
        self.assertIsNotNone(cipher1)
        self.assertEqual(msg1, pypre.decrypt(alice, cipher1))
        self.assertNotEqual(msg1, pypre.decrypt(bob, cipher1))

        token = pypre.generate_token(alice, bob)
        re_cipher1 = pypre.apply_token(token, cipher1)
        self.assertEqual(msg1, pypre.decrypt(bob, re_cipher1))
        self.assertNotEqual(msg1, pypre.decrypt(alice, re_cipher1))

        cipher2 = pypre.encrypt(alice, msg2)
        re_cipher2 = pypre.apply_token(token, cipher2)
        self.assertEqual(msg2, pypre.decrypt(bob, re_cipher2))
        self.assertNotEqual(msg2, pypre.decrypt(alice, re_cipher2))

        cipher3 = pypre.encrypt(bob, msg3)
        re_cipher3 = pypre.apply_token(token, cipher3)
        self.assertNotEqual(msg3, pypre.decrypt(bob, re_cipher3))
        self.assertNotEqual(msg3, pypre.decrypt(alice, re_cipher3))

class TestMessageConversion(unittest.TestCase):
    def test_msg_to_ints(self):
        msg1 = pypre.generate_msg()
        ints1 = pypre.msg_to_ints(msg1)
        self.assertIsNotNone(ints1)
        self.assertEqual(ints1, pypre.msg_to_ints(msg1))

        msg2 = pypre.generate_msg()
        ints2 = pypre.msg_to_ints(msg2)
        self.assertIsNotNone(ints2)
        self.assertEqual(ints2, pypre.msg_to_ints(msg2))

        self.assertNotEqual(ints1, ints2)

if __name__ == '__main__':
    unittest.main()

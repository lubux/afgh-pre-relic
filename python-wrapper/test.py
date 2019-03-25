import pypre
import unittest

class TestGenerationMethods(unittest.TestCase):
    def test_generate_params(self):
        params = pypre.generate_params()
        self.assertIsNotNone(params)

    def test_generate_sk(self):
        params = pypre.generate_params()
        sk = pypre.generate_sk(params)
        self.assertIsNotNone(sk)
        self.assertNotEqual(sk, pypre.generate_sk(params))

    def test_derive_pk(self):
        params = pypre.generate_params()
        sk1 = pypre.generate_sk(params)
        pk1 = pypre.derive_pk(params, sk1)
        sk2 = pypre.generate_sk(params)
        pk2 = pypre.derive_pk(params, sk2)

        self.assertIsNotNone(pk1)
        self.assertEqual(pk1, pypre.derive_pk(params, sk1))
        self.assertNotEqual(pk1, pk2)

    def test_generate_token(self):
        params = pypre.generate_params()
        alice_sk = pypre.generate_sk(params)
        alice_pk = pypre.derive_pk(params, alice_sk)
        bob_sk = pypre.generate_sk(params)
        bob_pk = pypre.derive_pk(params, bob_sk)

        token1 = pypre.generate_token(params, alice_sk, bob_pk)
        self.assertIsNotNone(token1)
        token2 = pypre.generate_token(params, alice_sk, bob_pk)
        self.assertIsNotNone(token2)
        token3 = pypre.generate_token(params, bob_sk, alice_pk)
        self.assertIsNotNone(token3)

        self.assertEqual(token1, token2)
        self.assertNotEqual(token1, token3)

    def test_rand_plaintext(self):
        plaintext1 = pypre.rand_plaintext()
        self.assertIsNotNone(plaintext1)
        plaintext2 = pypre.rand_plaintext()
        self.assertIsNotNone(plaintext2)
        self.assertNotEqual(plaintext1, plaintext2)

class TestEncryptionDecryption(unittest.TestCase):
    def test_encrypt(self):
        params = pypre.generate_params()
        alice_sk = pypre.generate_sk(params)
        alice_pk = pypre.derive_pk(params, alice_sk)
        bob_sk = pypre.generate_sk(params)
        bob_pk = pypre.derive_pk(params, bob_sk)

        plaintext1 = pypre.rand_plaintext()
        plaintext2 = pypre.rand_plaintext()

        self.assertIsNotNone(pypre.encrypt(params, alice_pk, plaintext1))
        self.assertNotEqual(pypre.encrypt(params, alice_pk, plaintext1), pypre.encrypt(params, alice_pk, plaintext1))
        self.assertNotEqual(pypre.encrypt(params, alice_pk, plaintext1), pypre.encrypt(params, bob_pk, plaintext1))
        self.assertNotEqual(pypre.encrypt(params, alice_pk, plaintext1), pypre.encrypt(params, alice_pk, plaintext2))

    def test_encrypt_decrypt(self):
        params = pypre.generate_params()
        alice_sk = pypre.generate_sk(params)
        alice_pk = pypre.derive_pk(params, alice_sk)
        bob_sk = pypre.generate_sk(params)
        bob_pk = pypre.derive_pk(params, bob_sk)

        plaintext = pypre.rand_plaintext()

        cipher = pypre.encrypt(params, alice_pk, plaintext)
        self.assertIsNotNone(cipher)
        self.assertEqual(plaintext, pypre.decrypt(params, alice_sk, cipher))
        self.assertNotEqual(plaintext, pypre.decrypt(params, bob_sk, cipher))

class TestReEncryption(unittest.TestCase):
    def test_re_encrypt(self):
        params = pypre.generate_params()
        alice_sk = pypre.generate_sk(params)
        alice_pk = pypre.derive_pk(params, alice_sk)
        bob_sk = pypre.generate_sk(params)
        bob_pk = pypre.derive_pk(params, bob_sk)

        plaintext1 = pypre.rand_plaintext()
        plaintext2 = pypre.rand_plaintext()
        plaintext3 = pypre.rand_plaintext()

        cipher = pypre.encrypt(params, alice_pk, plaintext1)
        self.assertIsNotNone(cipher)
        self.assertEqual(plaintext1, pypre.decrypt(params, alice_sk, cipher))
        self.assertNotEqual(plaintext1, pypre.decrypt(params, bob_sk, cipher))

        token = pypre.generate_token(params, alice_sk, bob_pk)
        re_cipher1 = pypre.apply_token(token, cipher)
        self.assertEqual(plaintext1, pypre.decrypt_re(params, bob_sk, re_cipher1))
        self.assertNotEqual(plaintext1, pypre.decrypt_re(params, alice_sk, re_cipher1))

        cipher2 = pypre.encrypt(params, alice_pk, plaintext2)
        re_cipher2 = pypre.apply_token(token, cipher2)
        self.assertEqual(plaintext2, pypre.decrypt_re(params, bob_sk, re_cipher2))
        self.assertNotEqual(plaintext2, pypre.decrypt_re(params, alice_sk, re_cipher2))

        cipher3 = pypre.encrypt(params, bob_pk, plaintext3)
        re_cipher3 = pypre.apply_token(token, cipher3)
        self.assertNotEqual(plaintext3, pypre.decrypt_re(params, bob_sk, re_cipher3))
        self.assertNotEqual(plaintext3, pypre.decrypt_re(params, alice_sk, re_cipher3))

class TestMessageConversion(unittest.TestCase):
    def test_plaintext_to_ints(self):
        plaintext1 = pypre.rand_plaintext()
        ints1 = pypre.plaintext_to_ints(plaintext1)
        self.assertIsNotNone(ints1)
        self.assertEqual(ints1, pypre.plaintext_to_ints(plaintext1))

        plaintext2 = pypre.rand_plaintext()
        ints2 = pypre.plaintext_to_ints(plaintext2)
        self.assertIsNotNone(ints2)
        self.assertEqual(ints2, pypre.plaintext_to_ints(plaintext2))

        self.assertNotEqual(ints1, ints2)

if __name__ == '__main__':
    unittest.main()

import unittest
import logging
import os
import tempfile

import integer
from elgamal import ElGamalKeypair, ElGamalCiphertext

logging.basicConfig(format='%(asctime)s %(module)s %(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


class ElGamalTestCase(unittest.TestCase):
    
    def setUp(self) -> None:
        super().setUp()

        self.keypair1 = ElGamalKeypair.construct(
            p=167,
            g=162,
            y=99,
            x=50
        )
        self.keypair1_pk = self.keypair1.only_public()

        self.keypair2 = ElGamalKeypair.generate(
            integer.get_probable_safe_prime(128)[0]
        )

        logger.info(f"keypair1 = {self.keypair1}")
        logger.info(f"keypair2 = {self.keypair2}")

    def test_encrypt_decrypt(self):
        """Tests whether encryption and decryption of a plaintext result in the same plaintext"""
        m = 122
        c = self.keypair1_pk.encrypt(m)
        logger.info(f"c = {c}")
        self.assertEqual(m, self.keypair1.decrypt(c))

    def test_encrypt_reblind_decrypt(self):
        """Tests the homomorphic property of the cryptosystem by reblinding a ciphertext and decrypting it"""
        m = self.keypair2.G_q.get_random_element()

        c = self.keypair2.encrypt(m)
        reblinded = self.keypair2.reblind(c)

        logger.info(f"m = {m}")
        logger.info(f"c = {c}")
        logger.info(f"reblinded = {reblinded}")

        self.assertNotEqual(c, reblinded)
        self.assertEqual(m, self.keypair2.decrypt(c))
        self.assertEqual(m, self.keypair2.decrypt(reblinded))

    def test_load_save(self):
        """Tests the methods for loading and saving elgamal keypairs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = os.path.join(tmpdir, "keypair1.json")
            file2 = os.path.join(tmpdir, "keypair1_pk.json")
            self.keypair1.save(file1)
            self.keypair1_pk.save(file2)

            k1 = ElGamalKeypair.load(file1)
            k1_pk = ElGamalKeypair.load(file2)
        m = k1.G_q.get_random_element()
        self.assertEqual(k1.decrypt(k1_pk.encrypt(m)), m)
        self.assertEqual(self.keypair1.decrypt(k1_pk.encrypt(m)), m)
        self.assertEqual(k1.decrypt(self.keypair1_pk.encrypt(m)), m)

    def test_sign_verify(self):
        """Tests the methods for message signing and signature verficiation"""
        m = self.keypair2.G_q.get_random_element()
        signature = self.keypair2.sign(m)
        self.assertTrue(self.keypair2.verify(m, signature))
        a, b = signature
        b = b + 1
        self.assertFalse(self.keypair2.verify(m, (a, b)))


if __name__ == '__main__':
    unittest.main()

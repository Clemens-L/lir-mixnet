import unittest
import logging

import zkps
from integer import SchnorrGroup, random_integer
from elgamal import ElGamalKeypair, ElGamalCiphertext

logging.basicConfig(format='%(asctime)s %(module)s %(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


class ZKPTestCase(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()

        self.keypair1 = ElGamalKeypair.construct(
            p=167,
            g=162,
            y=99,
            x=50
        )
        self.keypair1_pk = self.keypair1.only_public()

        logger.info(f"keypair1 = {self.keypair1}")

    def test_proof_of_correct_decryption(self):
        """Tests the ZKPoK that the plaintext of a ciphertext equals a known element."""
        m = 122
        r = 43
        c = self.keypair1_pk.encrypt(m, r)
        logger.info(f"c = {c}")

        # note how we only need the public key here
        proof = zkps.proof_correct_decryption(self.keypair1_pk, c, m, r)
        self.assertTrue(zkps.verify_correct_decryption(proof, self.keypair1_pk, c, m))

        wrong_m = 14
        wrong_proof = zkps.proof_correct_decryption(self.keypair1_pk, c, wrong_m, r)
        self.assertFalse(zkps.verify_correct_decryption(wrong_proof, self.keypair1_pk, c, wrong_m))

    def test_proof_of_plaintext_equality(self):
        """Tests the ZKPoK that a ciphertext is plaintext equal to another ciphertext"""
        m = 122
        m_wrong = 14
        r = 43
        r_prime = 32
        r_wrong = 12
        c = self.keypair1_pk.encrypt(m, r)
        c_prime = self.keypair1_pk.encrypt(m, r_prime)
        c_wrong = self.keypair1_pk.encrypt(m_wrong, r_wrong)
        c_reblinded = self.keypair1_pk.reblind(c, r_prime)

        proof = zkps.proof_plaintext_equality(self.keypair1_pk, c, r, c_prime, r_prime)
        self.assertTrue(zkps.verify_plaintext_equality(proof, self.keypair1_pk, c, c_prime))

        proof_wrong = zkps.proof_plaintext_equality(self.keypair1_pk, c, r, c_wrong, r_wrong)
        self.assertFalse(zkps.verify_plaintext_equality(proof_wrong, self.keypair1_pk, c, c_wrong))

        proof_reblinded = zkps.proof_plaintext_equality(self.keypair1_pk, c, r, c_reblinded, r + r_prime)
        self.assertTrue(zkps.verify_plaintext_equality(proof_reblinded, self.keypair1_pk, c, c_reblinded))

    def test_proof_of_plaintext_equality_or(self):
        """Tests the ZKPoK that a ciphertext is plaintext equal to at least one of the other given ciphertexts"""
        m = 122
        r = 43
        r_2 = 32
        r_3 = 12
        c = self.keypair1_pk.encrypt(m, r)
        c_2 = self.keypair1_pk.encrypt(m, r_2)
        c_0 = self.keypair1_pk.encrypt(self.keypair1_pk.G_q.get_random_element())
        c_1 = self.keypair1_pk.encrypt(self.keypair1_pk.G_q.get_random_element())
        c_3 = self.keypair1_pk.encrypt(14, r_3)

        proof = zkps.proof_plaintext_equality_or(self.keypair1_pk, c, r, [c_0, c_1, c_2, c_3], 2, r_2)
        logger.info(f"proof = {proof}")
        self.assertTrue(zkps.verify_plaintext_equality_or(proof, self.keypair1_pk, c, [c_0, c_1, c_2, c_3]))

        wrong_proof = zkps.proof_plaintext_equality_or(self.keypair1_pk, c, r, [c_0, c_1, c_2, c_3], 3, r_3)
        logger.info(f"wrong_proof = {wrong_proof}")
        self.assertFalse(zkps.verify_plaintext_equality_or(proof, self.keypair1_pk, c, [c_0, c_2, c_2, c_3]))

    def test_proof_of_plaintext_dlog_knowledge(self):
        """Tests the ZKPoK that the prover knows the discrete logarithm of an encrypted plaintext."""
        m = 122
        x = 23
        r = 43
        c = self.keypair1_pk.encrypt(self.keypair1_pk.G_q.powmod(m, x), r)

        proof = zkps.proof_plaintext_dlog(self.keypair1_pk, c, m, x, r)
        logger.info(f"proof = {proof}")
        self.assertTrue(zkps.verify_plaintext_dlog(proof, self.keypair1_pk, c, m))

        # this violates the proof of representation (as we do not know the correct exponent for m^x)
        wrong_proof1 = zkps.proof_plaintext_dlog(self.keypair1_pk, c, m, x+1, r)
        logger.info(f"wrong_proof1 = {wrong_proof1}")
        self.assertFalse(zkps.verify_plaintext_dlog(wrong_proof1, self.keypair1_pk, c, m))

        # this violates the proof of dlog equality between y^r and g^r (by changing the a component of the ciphertext)
        c_wrong = ElGamalCiphertext(c.G_q, c.G_q.powmod(c.a, 2), c.b)
        logger.info(f"c = {c} vs c_wrong = {c_wrong}")
        wrong_proof2 = zkps.proof_plaintext_dlog(self.keypair1_pk, c_wrong, m, x, r)
        logger.info(f"wrong_proof2 = {wrong_proof2}")
        self.assertFalse(zkps.verify_plaintext_dlog(wrong_proof2, self.keypair1_pk, c_wrong, m))

    def test_dlog_equals_double_dlog_proof(self):
        """Tests the ZKP that the dlog of A to the base h is equal to the double dlog of B to the bases g and y"""
        G_q = SchnorrGroup(167)
        G_r = SchnorrGroup(83)

        g = G_q.get_random_generator()
        h, y = G_r.get_random_generator(), G_r.get_random_generator()

        x = random_integer(0, G_r.order())

        A = G_r.powmod(h, x)
        B = G_q.powmod(g, G_r.powmod(y, x))

        proof = zkps.proof_dl_equal_ddl(G_q, G_r, g, h, y, A, B, x)

        self.assertTrue(zkps.verify_dl_equal_ddl(proof, G_q, G_r, g, h, y, A, B))

        wrong_proof = zkps.proof_dl_equal_ddl(G_q, G_r, g, h, y, A, B, x**x % G_r.p)

        self.assertFalse(zkps.verify_dl_equal_ddl(wrong_proof, G_q, G_r, g, h, y, A, B))


if __name__ == '__main__':
    unittest.main()

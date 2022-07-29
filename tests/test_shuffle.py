import unittest
import logging
import random
import integer
import settings
import shuffle
from shuffle import get_random_permutation, perform_random_shuffle, \
    generate_permutation_commitment, proof_of_shuffle_wikstroem, verify_proof_of_shuffle_wikstroem, \
    concatenate_permutations, invert_permutation, proof_of_inverse_permutation_commitment, \
    verify_inverse_permutation_commitment_proof
from elgamal import ElGamalKeypair


logging.basicConfig(format='%(asctime)s %(module)s %(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


class ShuffleTestCase(unittest.TestCase):

    def setUp(self) -> None:
        # pin seed
        super().setUp()

        integer.rng = random.Random(x=1)
        self.keypair_1 = ElGamalKeypair.generate(integer.get_probable_safe_prime(128)[0])
        self.keypair_2 = ElGamalKeypair.generate(settings.p, settings.g)
        self.keypair_2_pk = self.keypair_2.only_public()
        self.ciphertexts = [self.keypair_1.encrypt(self.keypair_1.G_q.get_random_element()) for _ in range(8)]
        self.ciphertexts2 = [self.keypair_2.encrypt(self.keypair_2.G_q.get_random_element()) for _ in range(8)]

    def test_get_random_permutation(self):
        """Tests whether a randomly generated permutation is indeed a valid permutation."""
        n = 5
        psi = get_random_permutation(n)
        for i in range(n):
            # each index must appear exactly once
            self.assertEqual(psi.count(i), 1)

    def test_concatenation_of_permutations(self):
        n = len(self.ciphertexts)
        m = 5

        perms = [get_random_permutation(n) for _ in range(m)]
        total_psi = concatenate_permutations(perms)

        permuted = self.ciphertexts
        for psi in perms:
            permuted, _, _ = perform_random_shuffle(permuted, self.keypair_1, psi)

        permuted_with_concatenation, _, _ = perform_random_shuffle(self.ciphertexts, self.keypair_1, total_psi)

        # compare output of applying the single permutations and the concatenation
        list1 = [self.keypair_1.decrypt(c) for c in permuted]
        list2 = [self.keypair_1.decrypt(c) for c in permuted_with_concatenation]
        self.assertListEqual(list1, list2)

    def test_inversion_of_permutation(self):
        n = len(self.ciphertexts)

        psi = get_random_permutation(n)
        psi_inv = invert_permutation(psi)

        permuted, _, _ = perform_random_shuffle(self.ciphertexts, self.keypair_1, psi)
        permuted_inv, _, _ = perform_random_shuffle(permuted, self.keypair_1, psi_inv)

        # order of plaintexts must be the same after applying psi followed by psi_inv
        plaintexts = [self.keypair_1.decrypt(c) for c in self.ciphertexts]
        plaintexts_permuted = [self.keypair_1.decrypt(c) for c in permuted_inv]
        self.assertListEqual(plaintexts, plaintexts_permuted)

    def test_perform_random_shuffle(self):
        """Tests random shuffling of elgamal ciphertexts after reblinding."""
        iterations = 100
        permuted = self.ciphertexts
        for _ in range(iterations):
            e, r, psi = perform_random_shuffle(permuted, self.keypair_1)
            _permuted = e
            for c in _permuted:
                # make sure all elements are reblinded
                self.assertNotIn(c, permuted)
            permuted = _permuted

        # set of all original messages
        set1 = set([self.keypair_1.decrypt(c) for c in self.ciphertexts])
        # set of all decrypted ciphertexts after shuffles
        set2 = set([self.keypair_1.decrypt(c) for c in permuted])

        self.assertSetEqual(set1, set2)

    def test_proof_of_shuffle_wikstroem(self):
        """Tests the commitment-consistent proof of shuffle by D. Wikstroem"""
        # shuffle ciphertexts
        e, r, psi = perform_random_shuffle(self.ciphertexts2, self.keypair_2_pk)
        # compute commitment
        c, r_com = generate_permutation_commitment(self.keypair_2_pk.G_q, settings.g, settings.h_i[:8], psi)
        # compute proof
        proof = proof_of_shuffle_wikstroem(self.keypair_2_pk.G_q, settings.g, settings.h, settings.h_i[:8],
                                           self.ciphertexts2, e, r, psi, c, r_com, self.keypair_2_pk)
        # verify proof (and consistency with commitment)
        self.assertTrue(verify_proof_of_shuffle_wikstroem(
            proof, self.keypair_2_pk.G_q, settings.g, settings.h, settings.h_i[:8], self.keypair_2_pk,
            [(elem.a, elem.b) for elem in self.ciphertexts2], [(elem.a, elem.b) for elem in e], c
        ))

    def test_proof_of_inverse_permutation_commitment(self):
        n = 4
        psi = get_random_permutation(n)
        psi_inv = invert_permutation(psi)

        h_i = settings.h_i[:n]

        c, r_com = generate_permutation_commitment(self.keypair_2_pk.G_q, settings.g, h_i, psi)
        c_inv, r_com_inv = generate_permutation_commitment(self.keypair_2_pk.G_q, settings.g, h_i, psi_inv)

        proof = proof_of_inverse_permutation_commitment(
            self.keypair_2_pk,
            c, c_inv,
            r_com, r_com_inv,
            psi, psi_inv
        )

        self.assertTrue(
            verify_inverse_permutation_commitment_proof(
                proof,
                self.keypair_2_pk,
                c, c_inv
            )
        )

    def test_escrowing_permutations_verifiably(self):
        """Tests the protocol for escrowing permutations verifiably yet secretly, using the public key of a trusted
        third party."""
        n = 4
        h_i = settings.h_i[:n]

        # generate permutation and commitment
        psi = shuffle.get_random_permutation(n)
        logger.info(f"psi = {psi}")
        c, r = shuffle.generate_permutation_commitment(settings.G_q, settings.g, h_i, psi)

        proof = shuffle.escrow_commitment(self.keypair_2_pk, settings.g, h_i, c, r, psi)
        _, _, Y, _, _, _, _ = proof
        self.assertTrue(shuffle.verify_escrowed_commitment(proof, self.keypair_2_pk, settings.g, h_i, c))

        extracted = shuffle.extract_escrowed_permutation(Y, h_i, self.keypair_2)
        logger.info(f"Extracted Psi: {extracted}")
        self.assertEqual(psi, extracted)


if __name__ == '__main__':
    unittest.main()

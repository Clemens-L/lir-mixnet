import logging
import hashlib
import math
from typing import List, Tuple, Any
from gmpy2 import mpz

import settings
import measurement
import zkps
from integer import SchnorrGroup, IntegerRandfunc, random_integer, Int
from elgamal import ElGamalKeypair, ElGamalCiphertext

logger = logging.getLogger(__name__)


def get_random_permutation(
    n: int, randfunc: IntegerRandfunc = random_integer
) -> List[int]:
    """
    Randomly generates a permutation of length n using Knuth's shuffle algorithm.
    :param n: Number of elements to permute.
    :param randfunc: Optionally, the random function to use
    :return: The random permutation (as a list of target indices)
    """

    # list of potential target positions
    t: List[int] = list(range(n))

    # final permutation (j[i] = position that the i-th element is permuted to)
    j: List[int] = []
    for i in range(n):
        # randomly choose target and store in permutation
        k = randfunc(i, n)
        j.append(t[k])
        # update possible targets
        t[k] = t[i]
    return j


def concatenate_permutations(perms: List[List[int]]) -> List[int]:
    """
    Concatenates a list of permutations.
    :param perms: List of permutations.
    :return: The permutation that is equivalent to the successive application of all psi \in perms.
    """
    n = len(perms[0])
    psi = list(range(n))
    for permutation in reversed(perms):
        psi = [permutation[psi[i]] for i in range(n)]
    return psi


def invert_permutation(psi: List[int]) -> List[int]:
    """
    Inverts a given permutation psi.
    :param psi: A permutation psi.
    :return: The inverse permutation of psi.
    """
    return [psi.index(i) for i in range(len(psi))]


def apply_permutation(elements: List[Any], psi: List[int]) -> List[Any]:
    """
    Applies a permutation to a list of elements to shuffle them.
    :param elements: List of elements of any type.
    :param psi: List of integers specifying the permutation psi.
    :return: Shuffled list of elements.
    """
    n = len(elements)
    assert n == len(psi)
    return [elements[psi[i]] for i in range(n)]


@measurement.measure("generate_permutation_commitment")
def generate_permutation_commitment(
    G_q: SchnorrGroup, g: mpz, h_i: List[mpz], psi: List[int]
) -> Tuple[List[mpz], List[mpz]]:
    """
    Commits to the columns of the permutation matrix of the permutation defined by indices in self.psi,
    using the pedersen commitment scheme.
    :return: A tuple (c, r), with c being the list of commitment values and r the list of random values used.
    """
    n = len(psi)

    # initialize lists of size n
    # (makes it easier to insert the r_ji and c_ji values)
    r: List[mpz] = [None] * n
    c: List[mpz] = [None] * n

    for i in range(n):
        r_ji = random_integer(0, G_q.order())
        c_ji = (G_q.powmod(g, r_ji) * h_i[i]) % G_q.p
        r[psi[i]] = r_ji
        c[psi[i]] = c_ji

    # make sure that none of the initial "None" values remained
    assert not r.count(None)
    assert not c.count(None)

    return c, r


@measurement.measure("perform_random_shuffle")
def perform_random_shuffle(
    ciphertexts: List[ElGamalCiphertext], key: ElGamalKeypair, psi: List[int] = None
) -> Tuple[List[ElGamalCiphertext], List[mpz], List[int]]:
    """
    Generates a random permutation and applies it to a list of ElGamal ciphertexts after reblinding them.
    :param ciphertexts: A list of ElGamal ciphertexts.
    :param key: The corresponding ElGamal key.
    :param psi: Optionally, a secret permutation (in the form of an index list).
    :return: A tuple (e, r, psi) of the permuted ciphertexts phi, the permuted random values r and the permutation psi.
    """
    n = len(ciphertexts)
    if not psi:
        psi = get_random_permutation(n)

    # reblind all ciphertexts
    r = [key.get_randomness() for _ in range(n)]
    e = [key.reblind(ciphertexts[i], r[i]) for i in range(n)]

    # apply permutation to reblinded ciphertexts
    e = apply_permutation(e, psi)

    return e, r, psi


ProofOfInversePermutationCommitment = Tuple[
    List[ElGamalCiphertext],
    List[ElGamalCiphertext],
    List[ElGamalCiphertext],
    List[zkps.DLEQProofTranscript],
    "ProofOfShuffleWikstroem",
    "ProofOfShuffleWikstroem"
]


@measurement.measure("proof_of_inverse_permutation_commitment")
def proof_of_inverse_permutation_commitment(
        pk: ElGamalKeypair,
        c: List[mpz],
        c_inv: List[mpz],
        r: List[mpz],
        r_inv: List[mpz],
        psi: List[int],
        psi_inv: List[int]
) -> ProofOfInversePermutationCommitment:
    """
    Performs a non-interactive zero-knowledge proof that the permutation commitment c_inv
    commits to the inverse of the permutation that c commits to.
    :param pk: ElGamal keypair to use in the proof
    :param c: Permutation commitment
    :param c_inv: Permutation commitment of inverse permutation
    :param r: Random values used to compute c
    :param r_inv: Random values used to compute c_inv
    :param psi: Permutation psi
    :param psi_inv: Inverse permutation psi_inv
    :return: Proof Transcript
    """
    n = len(c)
    assert n == len(c_inv) and n == len(r) and n == len(r_inv) and n == len(psi) and n == len(psi_inv)

    # create random ciphertexts
    r_begin = [pk.get_randomness() for _ in range(n)]
    e_begin = [pk.encrypt(pk.G_q.get_random_element(), r_begin[i]) for i in range(n)]

    # shuffle the random ciphertexts ...
    e1, r1, _ = perform_random_shuffle(e_begin, pk, psi)
    # ... and shuffle them back
    e2, r2, _ = perform_random_shuffle(e1, pk, psi_inv)

    # e_begin and e2 are plaintext equal (as we shuffled e_begin with psi, and then shuffled the result with psi_inv)
    # -> compute plaintext equality proofs to prove this
    plaintext_equality_proofs = [
        # due to reblinding, e2 ciphertexts have randomness r_begin + r1 + r2
        zkps.proof_plaintext_equality(pk, e_begin_i, r_begin_i, e2_i, (r_begin_i + r1_i + r2_i))
        # we need to apply psi_inv to the r2 values, so the randomness order matches the shuffled order
        for e_begin_i, r_begin_i, e2_i, r1_i, r2_i in zip(e_begin, r_begin, e2, r1, apply_permutation(r2, psi_inv))
    ]

    # finally, two proofs of shuffle (to show that e1 and e2 were computed correctly)
    h_i = settings.h_i[:n]
    proof_of_shuffle1 = proof_of_shuffle_wikstroem(
        pk.G_q, settings.g, settings.h, h_i, e_begin, e1, r1, psi, c, r, pk
    )
    proof_of_shuffle2 = proof_of_shuffle_wikstroem(
        pk.G_q, settings.g, settings.h, h_i, e1, e2, r2, psi_inv, c_inv, r_inv, pk
    )

    return e_begin, e1, e2, plaintext_equality_proofs, proof_of_shuffle1, proof_of_shuffle2


@measurement.measure("verify_inverse_permutation_commitment_proof")
def verify_inverse_permutation_commitment_proof(
        proof: ProofOfInversePermutationCommitment,
        pk: ElGamalKeypair,
        c: List[mpz],
        c_inv: List[mpz]
) -> bool:
    e_begin, e1, e2, plaintext_equality_proofs, proof_of_shuffle1, proof_of_shuffle2 = proof

    n = len(e_begin)
    assert n == len(e1) == len(e2) == len(plaintext_equality_proofs) == len(c) == len(c_inv)

    for e_begin_i, e2_i, plaintext_eq_proof in zip(e_begin, e2, plaintext_equality_proofs):
        if not zkps.verify_plaintext_equality(plaintext_eq_proof, pk, e_begin_i, e2_i):
            return False

    h_i = settings.h_i[:n]

    e_begin_unpacked = [(elem.a, elem.b) for elem in e_begin]
    e1_unpacked = [(elem.a, elem.b) for elem in e1]
    e2_unpacked = [(elem.a, elem.b) for elem in e2]

    return verify_proof_of_shuffle_wikstroem(
        proof_of_shuffle1, pk.G_q, settings.g, settings.h, h_i, pk,
        e_begin_unpacked, e1_unpacked, c
    ) and verify_proof_of_shuffle_wikstroem(
        proof_of_shuffle2, pk.G_q, settings.g, settings.h, h_i, pk,
        e1_unpacked, e2_unpacked, c_inv
    )


EscrowedCommitment = Tuple[
    List[ElGamalCiphertext],
    List[ElGamalCiphertext],
    List[ElGamalCiphertext],
    List[zkps.DLEQProofTranscript],
    List[zkps.DLEQProofTranscript],
    List[zkps.PlaintextEqualityORProof],
    List,
]


@measurement.measure("escrow_commitment")
def escrow_commitment(
    pk: ElGamalKeypair, g: mpz, h: List[mpz], c: List[mpz], r: List[mpz], psi: List[int]
) -> EscrowedCommitment:
    G_q = pk.G_q
    # encrypt the public generators h
    rh = [random_integer(0, G_q.order()) for _ in h]
    H = [pk.encrypt(h_i, rh_i) for h_i, rh_i in zip(h, rh)]
    # generate proofs that each H_i encrypts the correct h_i
    proof_H = [
        zkps.proof_correct_decryption(pk, H_i, h_i, rh_i)
        for H_i, h_i, rh_i in zip(H, h, rh)
    ]

    # invert psi
    psi_inv = [psi.index(i) for i in range(len(psi))]

    X = []
    Y = []
    proof_XY = []
    proof_Y = []
    proof_X = []

    for i in range(len(psi)):
        # first, we encrypt both factors of the commitment independently
        r_xi = random_integer(0, G_q.order())
        X_i = pk.encrypt(G_q.powmod(g, r[i]), r_xi)
        X.append(X_i)

        r_yi = random_integer(0, G_q.order())
        Y_i = pk.encrypt(h[psi_inv[i]], r_yi)
        Y.append(Y_i)

        # we can multiply both ciphertexts to obtain a ciphertext of the full commitment
        XY_i = X_i * Y_i
        # Proof 1: XY_i actually decrypts to c_i
        proof_XY_i = zkps.proof_correct_decryption(pk, XY_i, c[i], r_xi + r_yi)
        proof_XY.append(proof_XY_i)

        # Proof 2: Y_i is the encryption of one of the h-generators (but it must remain secret which one!)
        proof_Y_i = zkps.proof_plaintext_equality_or(
            pk, Y_i, r_yi, H, psi_inv[i], rh[psi_inv[i]]
        )
        proof_Y.append(proof_Y_i)

        # Proof 3: Prove that we know the discrete logarithm (base g) of the plaintext of X_i
        proof_X_i = zkps.proof_plaintext_dlog(pk, X_i, g, r[i], r_xi)
        proof_X.append(proof_X_i)

        logger.debug(f"encrypted commitment c_{i}")
    return H, X, Y, proof_H, proof_XY, proof_Y, proof_X


@measurement.measure("verify_escrowed_commitment")
def verify_escrowed_commitment(
    proof: EscrowedCommitment, pk: ElGamalKeypair, g: mpz, h: List[mpz], c: List[mpz]
) -> bool:
    H, X, Y, proof_H, proof_XY, proof_Y, proof_X = proof
    assert (
        len(H)
        == len(X)
        == len(Y)
        == len(proof_XY)
        == len(proof_Y)
        == len(proof_X)
        == len(c)
        == len(h)
    )

    b_proof_h = all(
        zkps.verify_correct_decryption(proof_H_i, pk, H_i, h_i)
        for proof_H_i, H_i, h_i in zip(proof_H, H, h)
    )

    b = []
    for X_i, Y_i, proof_XY_i, proof_Y_i, proof_X_i, c_i in zip(
        X, Y, proof_XY, proof_Y, proof_X, c
    ):
        XY_i = X_i * Y_i
        b.append(
            zkps.verify_correct_decryption(proof_XY_i, pk, XY_i, c_i)
            and zkps.verify_plaintext_equality_or(proof_Y_i, pk, Y_i, H)
            and zkps.verify_plaintext_dlog(proof_X_i, pk, X_i, g)
        )
    return all(b) and b_proof_h


def extract_escrowed_permutation(
    Y: List[ElGamalCiphertext], h: List[mpz], key: ElGamalKeypair
) -> List[int]:
    # decrypt ciphertexts
    y = [key.decrypt(Y_i) for Y_i in Y]
    return extract_escrowed_permutation_decrypted(y, h)


@measurement.measure("extract_escrowed_permutation_decrypted")
def extract_escrowed_permutation_decrypted(y: List[mpz], h: List[mpz]) -> List[int]:
    # order of the generators, as an index list (of their position in h), gives the inverse permutation
    psi_inv = [h.index(y_i) for y_i in y]
    # invert it
    psi = invert_permutation(psi_inv)
    return psi


ProofOfShuffleWikstroem = Tuple[
    Tuple[mpz, mpz, mpz, mpz, mpz, List[mpz]],  # t
    Tuple[mpz, mpz, mpz, mpz, List[mpz], List[mpz]],  # s
    List[mpz],  # c^hat
]


def compute_hash(values: List[Int]) -> mpz:
    h = hashlib.sha256()

    for val in values:
        # handle python ints by converting them to mpz first
        if not isinstance(val, type(mpz)):
            val = mpz(val)
        h.update(val.digits().encode())
    c = mpz(int.from_bytes(bytes=h.digest(), byteorder="little"))
    return c


def generate_commitment_chain(
    G_q: SchnorrGroup, g: mpz, initial: mpz, u: List[mpz]
) -> Tuple[List[mpz], List[mpz]]:
    """
    Commits to a list of public challenges u, generating a chain of commitments starting with a given initial value.
    :param initial: Initial challenge c[-1]
    :param u: List of public challenges.
    :return: A tuple (c, r), with c being the list of commitment values and r the list of random values used.
    """
    n = len(u)

    # generate random values for each commitment
    r = [random_integer(0, G_q.order()) for _ in range(n)]
    # commit to the initial value
    c = [G_q.powmod(g, r[0]) * G_q.powmod(initial, u[0]) % G_q.p]
    # commit to the values 1..n-1
    for i in range(1, n):
        c.append(G_q.powmod(g, r[i]) * G_q.powmod(c[i - 1], u[i]) % G_q.p)

    return c, r


@measurement.measure("proof_of_shuffle")
def proof_of_shuffle_wikstroem(
    G_q: SchnorrGroup,
    g: mpz,
    h: mpz,
    h_i: List[mpz],
    e: List[ElGamalCiphertext],
    e_prime: List[ElGamalCiphertext],
    r: List[mpz],
    psi: List[int],
    c: List[mpz],
    r_com: List[mpz],
    key: ElGamalKeypair,
) -> ProofOfShuffleWikstroem:
    """
    Computes the commitment-consistent proof of a shuffle by D. Wikström.
    :param G_q: Group of prime order q
    :param g: Public generator of G_q
    :param h: Public generator of G_q
    :param h_i: List of N public generators of G_q
    :param e: List of N ElGamal ciphertexts
    :param e_prime: List of N permuted and reblinded ElGamal ciphertexts
    :param r: (Permuted) Random values used during the reblinding of the ciphertexts
    :param psi: List of N indices used to permute the ciphertexts
    :param c: Commitment to permutation psi
    :param r_com: Random values used in the commitment to psi
    :param key: ElGamal (public) key used in the (re-)encryption of the ciphertexts
    :return: A proof transcript (t, s, c^hat)
    """
    assert len(h_i) == len(e)
    assert len(h_i) == len(e_prime)
    assert len(h_i) == len(r)
    assert len(h_i) == len(psi)

    n = len(psi)
    logger.debug(f"psi = {psi}")

    # Generate challenges u using the hash-method
    # Compute u_prime by applying psi
    u = [
        compute_hash(
            [e.a for e in e]
            + [e.b for e in e]
            + [e.a for e in e_prime]
            + [e.b for e in e_prime]
            + c
            + [i]
        )
        % G_q.order()
        for i in range(n)
    ]

    logger.debug(f"u = {u}")
    u_prime = [u[psi[i]] for i in range(n)]
    logger.debug(f"u_prime = {u_prime}")

    # commitments to the challenges u_prime
    c_hat, r_hat = generate_commitment_chain(G_q, g, h, u_prime)

    r_sum = sum(r_com) % G_q.order()

    v: List[mpz] = [None] * n
    v[n - 1] = mpz(1)
    for i in reversed(range(n - 1)):
        v[i] = (u_prime[i + 1] * v[i + 1]) % G_q.order()

    r_hat_sum = sum(r_i_hat * v_i for r_i_hat, v_i in zip(r_hat, v)) % G_q.order()

    r_tilde_sum = sum(r_i * u_i for r_i, u_i in zip(r_com, u)) % G_q.order()

    r_prime_sum = sum(r_i_prime * u_i for r_i_prime, u_i in zip(r, u)) % G_q.order()

    w = [random_integer(0, G_q.order()) for _ in range(4)]
    w_hat = [random_integer(0, G_q.order()) for _ in range(n)]
    w_prime = [random_integer(0, G_q.order()) for _ in range(n)]

    t1 = G_q.powmod(g, w[0])
    t2 = G_q.powmod(g, w[1])
    t3 = (
        G_q.powmod(g, w[2])
        * math.prod(G_q.powmod(h_i[i], w_prime[i]) for i in range(n))
        % G_q.p
    )

    pk = key.y
    t4_1 = (
        G_q.powmod(pk, -w[3])
        * math.prod(
            G_q.powmod(ciphertext.b, w_prime_i)
            for ciphertext, w_prime_i in zip(e_prime, w_prime)
        )
    ) % G_q.p
    t4_2 = (
        G_q.powmod(g, -w[3])
        * math.prod(
            G_q.powmod(ciphertext.a, w_prime_i)
            for ciphertext, w_prime_i in zip(e_prime, w_prime)
        )
    ) % G_q.p

    t_hat = [G_q.powmod(g, w_hat[0]) * G_q.powmod(h, w_prime[0]) % G_q.p]
    for i in range(1, n):
        t_hat.append(
            G_q.powmod(g, w_hat[i]) * G_q.powmod(c_hat[i - 1], w_prime[i]) % G_q.p
        )

    t = t1, t2, t3, t4_1, t4_2, t_hat

    challenge = (
        compute_hash(
            [e.a for e in e]
            + [e.b for e in e]
            + [e.a for e in e_prime]
            + [e.b for e in e_prime]
            + c
            + c_hat
            + [pk]
            + [t1, t2, t3, t4_1, t4_2]
            + t_hat
        )
        % G_q.order()
    )
    logger.debug(f"challenge = {challenge}")

    s_i = [
        (w_i + challenge * r) % G_q.order()
        for w_i, r in [
            (w[0], r_sum),
            (w[1], r_hat_sum),
            (w[2], r_tilde_sum),
            (w[3], r_prime_sum),
        ]
    ]
    s_hat = [(w_hat[i] + challenge * r_hat[i]) % G_q.order() for i in range(n)]
    s_prime = [(w_prime[i] + challenge * u_prime[i]) % G_q.order() for i in range(n)]

    s = s_i[0], s_i[1], s_i[2], s_i[3], s_hat, s_prime

    proof = t, s, c_hat
    logger.debug({"t": t, "s": s, "c_hat": c_hat})

    logger.debug(f"proof = {proof}")

    return proof


@measurement.measure("verify_proof_of_shuffle")
def verify_proof_of_shuffle_wikstroem(
    proof: ProofOfShuffleWikstroem,
    G_q: SchnorrGroup,
    g: mpz,
    h: mpz,
    h_i: List[mpz],
    key: ElGamalKeypair,
    e: List[Tuple[mpz, mpz]],
    e_prime: List[Tuple[mpz, mpz]],
    c: List[mpz],
) -> bool:
    """
    Verifies a commitment-consistent proof of a shuffle by D. Wikström.
    :param proof: A proof transcript (t, s, c^hat)
    :param G_q: Group of prime order q
    :param g: Public generator of G_q
    :param h: Public generator of G_q
    :param h_i: List of N public generators of G_q
    :param key: ElGamal (public) key used in the (re-)encryption of the ciphertexts
    :param e: List of N ElGamal ciphertexts
    :param e_prime: List of N permuted and reblinded ElGamal ciphertexts
    :param c: Commitment to permutation psi
    :return: True, iff the verification is successful.
    """
    t, s, c_hat = proof
    t1, t2, t3, t4_1, t4_2, t_hat = t
    s1, s2, s3, s4, s_hat, s_prime = s

    n = len(e)

    u = [
        compute_hash(
            [a for a, _ in e]
            + [b for _, b in e]
            + [a for a, _ in e_prime]
            + [b for _, b in e_prime]
            + c
            + [i]
        )
        % G_q.order()
        for i in range(n)
    ]
    logger.debug(f"u = {u}")

    c_vinc = (
        math.prod(c_i for c_i in c) * G_q.powmod(math.prod(h for h in h_i), -1) % G_q.p
    )
    u_prod = math.prod(u_i for u_i in u) % G_q.order()
    c_hat_quot = c_hat[n - 1] * G_q.powmod(h, -u_prod) % G_q.p
    c_tilde = math.prod(G_q.powmod(c[i], u[i]) for i in range(n)) % G_q.p

    a_prime = math.prod(G_q.powmod(a_i, u_i) for (a_i, _), u_i in zip(e, u)) % G_q.p
    b_prime = math.prod(G_q.powmod(b_i, u_i) for (_, b_i), u_i in zip(e, u)) % G_q.p

    challenge = (
        compute_hash(
            [a for a, _ in e]
            + [b for _, b in e]
            + [a for a, _ in e_prime]
            + [b for _, b in e_prime]
            + c
            + c_hat
            + [key.y]
            + [t1, t2, t3, t4_1, t4_2]
            + t_hat
        )
        % G_q.order()
    )

    logger.debug(f"challenge = {challenge}")

    t1_prime = G_q.powmod(c_vinc, -challenge) * G_q.powmod(g, s1) % G_q.p
    t2_prime = G_q.powmod(c_hat_quot, -challenge) * G_q.powmod(g, s2) % G_q.p

    t3_prime = (
        G_q.powmod(c_tilde, -challenge)
        * G_q.powmod(g, s3)
        * math.prod(
            G_q.powmod(_h_i, s_prime_i) for _h_i, s_prime_i in zip(h_i, s_prime)
        )
        % G_q.p
    )

    t4_1_prime = (
        G_q.powmod(b_prime, -challenge)
        * G_q.powmod(key.y, -s4)
        * math.prod(
            G_q.powmod(b_prime_i, s_prime_i)
            for (_, b_prime_i), s_prime_i in zip(e_prime, s_prime)
        )
        % G_q.p
    )

    t4_2_prime = (
        G_q.powmod(a_prime, -challenge)
        * G_q.powmod(g, -s4)
        * math.prod(
            G_q.powmod(a_prime_i, s_prime_i)
            for (a_prime_i, _), s_prime_i in zip(e_prime, s_prime)
        )
        % G_q.p
    )

    t_hat_prime = [
        G_q.powmod(c_hat[0], -challenge)
        * G_q.powmod(g, s_hat[0])
        * G_q.powmod(h, s_prime[0])
        % G_q.p
    ]
    t_hat_prime += [
        G_q.powmod(c_hat[i], -challenge)
        * G_q.powmod(g, s_hat[i])
        * G_q.powmod(c_hat[i - 1], s_prime[i])
        % G_q.p
        for i in range(1, n)
    ]

    logger.debug(f"t1 = {t1} and t1_prime = {t1_prime}")
    logger.debug(f"t2 = {t2} and t2_prime = {t2_prime}")
    logger.debug(f"t3 = {t3} and t3_prime = {t3_prime}")
    logger.debug(
        f"t4_1, t4_2 = {(t4_1, t4_2)} and t4_1_prime, t4_2_prime = {(t4_1_prime, t4_2_prime)}"
    )
    logger.debug(f"t_hat = {t_hat} and t_hat_prime = {t_hat_prime}")

    result = (
        (t1 == t1_prime)
        and (t2 == t2_prime)
        and (t3 == t3_prime)
        and (t4_1 == t4_1_prime)
        and (t4_2 == t4_2_prime)
        and (t_hat == t_hat_prime)
    )
    return result

import asyncio
import logging
import math
import json
import os
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from gmpy2 import mpz, invert

import measurement
import protocols
import settings
import elgamal
from integer import SchnorrGroup, random_integer, IntJSONEncoder, IntJSONDecoder
from zkps import proof_dleq, verify_dleq, DLEQProofTranscript

logger = logging.getLogger(__name__)


DecryptionShare = Tuple[mpz, DLEQProofTranscript]


class DistributedKeyGeneration(protocols.ProtocolState):
    """
    Implements the "New-DKG" protocol by Gennaro (2007).
    Allows n peers to generate an ElGamal keypair s.t. each
    peer only has a secret share of the private key.

    Two phases:
        - Generating private key x
        - Extracting public key y = g^x using the secret shares of x

    Generating x:
        - All peers share random value z_i using Pedersen-VSS
            - choose two random polynomials (a_i0 = z_i)
            - send points on both polynomials to peers
            - peers verify received shares
            - complaint phase, build set of qualified parties QUAL
            - x = sum_{i \in QUAL} z_i
            - shares of x: x_i = \sum_{j \in QUAL} s_ji
    Extracting y = g^x
        -
    """

    def __init__(self, tid: str) -> None:
        super().__init__(tid)

        self.G_q: Optional[SchnorrGroup] = None
        self.g: mpz = None
        self.h: mpz = None
        self.t: int = 0

        self.commitments: Dict[int, List[mpz]] = {}
        self.shares: Dict[int, Tuple[mpz, mpz]] = {}
        self.shares_sent: Dict[int, Tuple[mpz, mpz]] = {}
        self.revealed_shares: Dict[int, List[Tuple[int, mpz, mpz]]] = {}
        self.extraction_commitments: Dict[int, List[mpz]] = {}
        self.complaints_1: Dict[int, List[int]] = {}
        self.qual: List[int] = []
        self.qual_without_self: List[int] = []

        self.x_i: mpz = None
        self.x_i_prime: mpz = None
        self.v: Dict[int, mpz] = {}
        self.y: mpz = None

        self.f: List[mpz] = []

        self.has_dealt = False

        self.sent_commitments = asyncio.Future()
        self.sent_shares = asyncio.Future()
        self.sent_complaints_1 = asyncio.Future()
        self.sent_extraction_commitments = asyncio.Future()
        self.received_all_commitments = asyncio.Future()
        self.received_all_shares = asyncio.Future()
        self.received_all_complaints_1 = asyncio.Future()
        self.received_revealed_shares_from = [asyncio.Future() for _ in range(settings.NUM_PEERS)]
        # (used when extracting the public key y)
        self.received_all_extraction_commitments = asyncio.Future()
        self.done = asyncio.Future()

    def set_params(
            self,
            G_q: SchnorrGroup,
            g: mpz,
            h: mpz,
            t: int,
    ):
        self.G_q = G_q
        self.g = g
        self.h = h
        # t = 0 is valid, every peer can then decrypt by themselves
        assert 0 <= t < settings.NUM_PEERS
        self.t = t

    def random_polynomial(self, t: int, a_0: mpz) -> List[mpz]:
        """
        Returns a random polynomial p of degree t that satisfies p(0) = a_0.
        :param t: Degree of the polynomial.
        :param a_0: Coefficient a_0 of the polynomial.
        :return: List of the coefficients that define the polynomial.
        """
        coeffs = [a_0]
        coeffs = coeffs + [random_integer(0, self.G_q.order()) for _ in range(0, t)]
        return coeffs

    def eval_polynomial(self, coeffs: List[mpz], x: mpz) -> mpz:
        # do not use powmod for x^j, as polynomial can be evaluated for x that are not in G_q
        return sum([coeffs[j] * (x ** j) for j in range(len(coeffs))]) % self.G_q.order()

    @staticmethod
    def get_peer_index(i: int) -> int:
        """
        Given a peer id, this method returns the position that is evaluated on the polynomial for that peer.
        (i.e., get_peer_index(0) returns 1, -> p(1) is evaluated to generate the share for peer 0)
        :param i: Id of the peer
        :return: The position at which the polynomial should be evaluated
        """
        return i + 1

    def has_received_all_commitments(self) -> bool:
        return len(self.commitments.keys()) == settings.NUM_PEERS

    def has_received_all_shares(self) -> bool:
        return len(self.shares.keys()) == settings.NUM_PEERS

    def has_received_all_complaints_1(self) -> bool:
        return len(self.complaints_1.keys()) == settings.NUM_PEERS

    def has_received_all_extraction_commitments(self) -> bool:
        return len(self.extraction_commitments.keys()) == settings.NUM_PEERS

    @classmethod
    def load(cls, filename: str) -> "DistributedKeyGeneration":
        """
        Initializes a DistributedKeyGeneration-object from stored JSON-values.
        Note that this object is not fully functional. It should only be used for threshold decryption.
        :param filename: The path to the JSON-file.
        :return: A partial DistributedKeyGeneration-object.
        """
        obj = cls.init_new()

        with open(filename, mode="r") as fp:
            data = json.load(fp, cls=IntJSONDecoder)

        obj.G_q = SchnorrGroup(data["p"])
        obj.g = data["g"]
        obj.t = data["t"]
        obj.y = data["y"]
        obj.x_i = data["x_i"]
        # (convert keys back to integers)
        obj.v = {int(k): v for k, v in data["v"].items()}

        obj.qual = data["qual"]
        obj.qual_without_self = data["qual_without_self"]

        return obj

    def save(self, filename: str) -> None:
        """
        Saves this objects relevant information (i.e. all values requried for threshold decryption) to a JSON-file.
        :param filename: The path to the JSON-file.
        """
        data = {
            "p": self.G_q.p,
            "g": self.g,
            "t": self.t,
            "y": self.y,
            "x_i": self.x_i,
            "v": self.v,
            "qual": self.qual,
            "qual_without_self": self.qual_without_self
        }

        Path(os.path.dirname(filename)).mkdir(parents=True, exist_ok=True)
        with open(filename, mode="w+") as fp:
            json.dump(data, fp, cls=IntJSONEncoder)

    async def save_all(self, filenames: List[str]) -> None:
        """
        Notifies all peers i to save their DKG information to their respective file (located at filenames[i])
        :param filenames: A list of NUM_PEERS filenames.
        """
        assert len(filenames) == settings.NUM_PEERS
        for i in range(settings.NUM_PEERS):
            if i == settings.PEER_ID:
                self.save(filenames[i])
            else:
                msg = self.base_msg()
                msg["save"] = filenames[i]
                await self.send_msg(i, msg)

    @property
    def public_key(self) -> elgamal.ElGamalKeypair:
        """
        Creates an ElGamalKeypair object representing the public key of this distributed key generation.
        :return: The public key object.
        """
        assert self.y
        return elgamal.ElGamalKeypair.construct(self.G_q.p, self.g, self.y)

    @measurement.measure("gen_decryption_share")
    def gen_decryption_share(self, c: elgamal.ElGamalCiphertext) -> Dict[int, DecryptionShare]:
        """
        Generates a decryption share for the given ciphertext, using the peers' share of the secret key.
        :param c: ElGamal Ciphertext encrypted with self.y
        :return: A decryption share {i: c.a^x_i}, where i is our peer index and a transcript of the correctness proof
        """
        share = self.G_q.powmod(c.a, self.x_i)
        proof = proof_dleq(self.G_q, self.g, self.v[self.get_peer_index(settings.PEER_ID)], c.a, share, self.x_i)

        if settings.MALICIOUS_THRES_DECR:
            # this peer is malicious during threshold decryption
            # send a random share to prevent decryption
            share = self.G_q.get_random_element()

        return {settings.PEER_ID: (share, proof)}

    @measurement.measure("combine_decryption_shares")
    def combine_decryption_shares(self, c: elgamal.ElGamalCiphertext, shares: Dict[int, DecryptionShare]) -> mpz:
        """
        Combines t+1 correct decryption shares using Lagrange interpolation, resulting in the plaintext.
        :param c: The ciphertext to be decrypted.
        :param shares: A dictionary of at least t+1 decryption shares, along with their proofs of correctness.
        :return: The plaintext obtained after decryption.
        """
        assert len(shares.keys()) >= self.t + 1
        # explicitly typecast key to int, as dicts received from peers have keys of type str
        s = [(self.get_peer_index(int(i)), share) for i, share in shares.items()]

        # verify proofs of correctness and filter out invalid shares
        s_qual = []
        for i, share_and_proof in s:
            share, proof = share_and_proof
            correct = verify_dleq(self.G_q, proof, self.g, self.v[i], c.a, share)
            if not correct:
                logger.error(f"decryption share supplied by peer {i-1} was incorrect!")
            else:
                s_qual.append((i, share))

        if len(s_qual) < self.t + 1:
            # not enough correct shares were received
            logger.error(f"Only {len(s_qual)} out of {self.t + 1} required shares are present. Cannot decrypt.")
            raise RuntimeError("Threshold decryption failed.")

        # perform lagrange interpolation
        def lagrange_coeff(i: int) -> mpz:
            nominator = math.prod(j for j, _ in s_qual if j != i)
            denominator = math.prod(j - i for j, _ in s_qual if j != i)
            return (nominator * invert(denominator, self.G_q.order())) % self.G_q.order()
        ax = math.prod(self.G_q.powmod(share, lagrange_coeff(i)) for i, share in s_qual) % self.G_q.p

        return c.b * invert(ax, self.G_q.p) % self.G_q.p

    async def share_parameters(self):
        msg = self.base_msg()
        msg["p"] = self.G_q.p
        msg["g"] = self.g
        msg["h"] = self.h
        msg["t"] = self.t
        await self.send_msg(self.ALL_PEERS, msg)

    async def perform_deal_randomness(self):
        logger.debug(f"Starting dealing phase (Randomness)")
        # Here we perform a Pedersen-VSS of a random value z_i
        # All peers do this, and the secret key is the sum of all z_i

        # our contribution to the secret key
        z = random_integer(0, self.G_q.order())
        logger.debug(f"z = {z}")

        # two random polynomials, f(0) = z, f_prime(0) = random
        f = self.random_polynomial(self.t, z)
        self.f = f
        f_prime = self.random_polynomial(self.t, random_integer(0, self.G_q.order()))

        # commitments to coefficients
        C = [
            self.G_q.powmod(self.g, a) * self.G_q.powmod(self.h, b) % self.G_q.p
            for a, b in zip(f, f_prime)
        ]
        self.commitments[settings.PEER_ID] = C

        # broadcast commitments
        msg_commitments = self.base_msg()
        msg_commitments["C"] = C
        await self.send_msg(self.ALL_PEERS, msg_commitments)

        self.sent_commitments.set_result(True)

        # compute shares for each peer
        s = {
            i: self.eval_polynomial(f, self.get_peer_index(i))
            for i in settings.all_peer_ids()
        }
        s_prime = {
            i: self.eval_polynomial(f_prime, self.get_peer_index(i))
            for i in settings.all_peer_ids()
        }

        if settings.MALICIOUS_DKG:
            # this peer is malicious during DKG
            # randomly decide to either manipulate one or all shares
            if random_integer(0, 2):
                # corrupt single pair of shares
                s[settings.all_peer_ids()[0]] = self.G_q.get_random_element()
                s_prime[settings.all_peer_ids()[0]] = self.G_q.get_random_element()
            else:
                # we corrupt all our shares
                s = {k: self.G_q.get_random_element() for k, _ in s.items()}
                s_prime = {k: self.G_q.get_random_element() for k, _ in s_prime.items()}

        # we need to give ourselves a share as well
        peer_idx = self.get_peer_index(settings.PEER_ID)
        self.shares[settings.PEER_ID] = self.eval_polynomial(f, peer_idx), self.eval_polynomial(f_prime, peer_idx)

        self.shares_sent = {
            i: (s[i], s_prime[i]) for i in settings.all_peer_ids()
        }

        # send the secret shares to each peer
        for j in settings.all_peer_ids():
            msg_shares = self.base_msg()
            msg_shares["s"] = s[j]
            msg_shares["s_prime"] = s_prime[j]
            await self.send_msg(j, msg_shares)

        self.sent_shares.set_result(True)

        await self.perform_verify_randomness()

    def verify_secret_shares(self, i: int, j: int, s_ij: mpz, s_ij_prime: mpz) -> bool:
        lhs = self.G_q.powmod(self.g, s_ij) * self.G_q.powmod(self.h, s_ij_prime) % self.G_q.p
        rhs = math.prod(
            self.G_q.powmod(self.commitments[i][k], self.get_peer_index(j) ** k)
            for k in range(self.t + 1)
        ) % self.G_q.p
        return lhs == rhs

    def complaints_against_peer(self, i: int) -> List[int]:
        return [k for k in self.complaints_1 if i in self.complaints_1[k]]

    def num_complaints_against_peer(self, i: int) -> int:
        return len(self.complaints_against_peer(i))

    async def perform_verify_randomness(self):
        logger.debug(f"Starting verification phase (Randomness)")
        await asyncio.gather(self.received_all_commitments, self.received_all_shares)

        complaints = []

        for i in settings.all_peer_ids():
            s_ij, s_ij_prime = self.shares[i]
            if not self.verify_secret_shares(i, settings.PEER_ID, s_ij, s_ij_prime):
                logger.error(f"secret shares of peer {i} were incorrect. complaining ...")
                complaints.append(i)

        self.complaints_1[settings.PEER_ID] = complaints

        # broadcast our complains
        msg = self.base_msg()
        msg["complaints_1"] = complaints
        await self.send_msg(self.ALL_PEERS, msg)
        self.sent_complaints_1.set_result(True)

        await self.received_all_complaints_1

        # if 0 < n <= t peers complained against us, reveal the corresponding s_ij and s_ij_prime values
        if 0 < self.num_complaints_against_peer(settings.PEER_ID) <= self.t:
            logger.info(f"We received complaints, revealing shares ...")
            complaints = self.complaints_against_peer(settings.PEER_ID)
            revealed_shares = [(i, self.shares_sent[i][0], self.shares_sent[i][0]) for i in complaints]
            logger.debug(f"{revealed_shares=}")
            self.revealed_shares[settings.PEER_ID] = revealed_shares
            msg = self.base_msg()
            msg["revealed_shares"] = revealed_shares
            await self.send_msg(self.ALL_PEERS, msg)
            self.received_revealed_shares_from[settings.PEER_ID].set_result(True)

        # wait for all shares to be revealed by peers who received 0 < n <= t complaints
        await asyncio.gather(*[
            self.received_revealed_shares_from[i]
            for i in range(settings.NUM_PEERS)
            if 0 < self.num_complaints_against_peer(i) <= self.t
        ])

        # build set of non-disqualified parties
        peers_that_revealed = [
            i
            for i in range(settings.NUM_PEERS)
            if 0 < self.num_complaints_against_peer(i) <= self.t
        ]
        peers_that_revealed_incorrectly = [
            j
            for j in peers_that_revealed
            if not all(
                self.verify_secret_shares(i, j, s_ij, s_ij_prime)
                for i, s_ij, s_ij_prime in self.revealed_shares[j]
            )
        ]
        peers_too_many_complaints = [
            i
            for i in range(settings.NUM_PEERS)
            if self.num_complaints_against_peer(i) > self.t
        ]
        self.qual = [
            i for i in range(settings.NUM_PEERS)
            if i not in peers_that_revealed_incorrectly
            if i not in peers_too_many_complaints
        ]
        self.qual_without_self = [i for i in self.qual if i != settings.PEER_ID]
        logger.info(f"{peers_that_revealed=} "
                    f"{peers_that_revealed_incorrectly=} "
                    f"{peers_too_many_complaints=} "
                    f"{self.qual=}"
                    )

        # compute our share of the secret (using only the shares from qualified parties)
        self.x_i = sum(self.shares[j][0] for j in self.qual) % self.G_q.order()
        logger.debug(f"key share: {self.x_i}")
        self.x_i_prime = sum(self.shares[j][1] for j in self.qual) % self.G_q.order()

        # if the verification was successful: continue with extracting the public key
        await self.perform_deal_extraction()

    async def perform_deal_extraction(self):
        logger.debug(f"Starting dealing phase (extraction)")
        A = [self.G_q.powmod(self.g, self.f[k]) for k in range(self.t + 1)]

        self.extraction_commitments[settings.PEER_ID] = A

        # broadcast commitments to coefficients
        msg = self.base_msg()
        msg["A"] = A
        await self.send_msg(self.ALL_PEERS, msg)

        self.sent_extraction_commitments.set_result(True)

        await self.perform_verify_extraction()

    def verify_extraction_commitments(self, i: int, j: int) -> bool:
        s_ij, _ = self.shares[i]
        A_i = self.extraction_commitments[i]
        lhs = self.G_q.powmod(self.g, s_ij)
        rhs = math.prod(
            self.G_q.powmod(A_i[k], self.get_peer_index(settings.PEER_ID) ** k) for k in
            range(self.t + 1)) % self.G_q.p
        logger.debug(f"verify extraction commitment from {i} to peer {j}: {lhs == rhs}")
        return lhs == rhs

    async def perform_verify_extraction(self):
        logger.debug(f"Starting verification phase (extraction)")
        await self.received_all_extraction_commitments

        # for all qualified peers (except us)
        for i in self.qual_without_self:
            assert self.verify_extraction_commitments(i, settings.PEER_ID)
            # TODO: blaming phase (and reconstruction of the secrets of malicious peers)

        y_i = [self.extraction_commitments[i][0] for i in self.qual_without_self] + [
            self.G_q.powmod(self.g, self.f[0])]
        self.y = math.prod(y_i) % self.G_q.p

        # compute v_i's for verification of correctness proofs of decryption shares
        for i in self.qual:
            v_i = math.prod(
                math.prod(self.G_q.powmod(self.extraction_commitments[j][k], self.get_peer_index(i) ** k)
                          for k in range(self.t + 1)) % self.G_q.p
                for j in self.qual
            ) % self.G_q.p
            self.v[self.get_peer_index(i)] = v_i
        self.v[self.get_peer_index(settings.PEER_ID)] = self.G_q.powmod(self.g, self.x_i)

        logger.debug(f"Extracted public key y = {self.y}")
        self.done.set_result(True)

    # while this measurement is only done for the initiating peer, it measures the duration
    # of the complete DKG protocol
    @measurement.measure_async("dkg_perform")
    async def perform(self) -> None:
        await self.share_parameters()

        self.has_dealt = True
        await self.perform_deal_randomness()

        await self.done

    async def process(self, msg: Dict) -> None:
        if {"p", "g", "h", "t"} <= msg.keys():
            self.set_params(SchnorrGroup(msg["p"]), msg["g"], msg["h"], msg["t"])

        if not self.has_dealt and self.G_q is not None:
            self.has_dealt = True
            await self.perform_deal_randomness()

        from_id = msg["from_id"]
        if "C" in msg.keys():
            await self.sent_commitments
            self.commitments[from_id] = msg["C"]
            if self.has_received_all_commitments():
                logger.debug(f"Received all commitments.")
                self.received_all_commitments.set_result(True)
        elif {"s", "s_prime"} <= msg.keys():
            await self.sent_shares
            self.shares[from_id] = (msg["s"], msg["s_prime"])
            if self.has_received_all_shares():
                logger.debug(f"Received all shares.")
                self.received_all_shares.set_result(True)
        elif "complaints_1" in msg.keys():
            await self.sent_complaints_1
            self.complaints_1[from_id] = msg["complaints_1"]
            if self.has_received_all_complaints_1():
                logger.debug(f"Received all complaints 1")
                self.received_all_complaints_1.set_result(True)
        elif "revealed_shares" in msg.keys():
            self.revealed_shares[from_id] = msg["revealed_shares"]
            # verify that the revealed shares are complete
            required_revealed_shares = set(self.complaints_against_peer(from_id))
            delivered_revealed_shares = set([i for i, _, _ in msg["revealed_shares"]])
            missing_shares = required_revealed_shares - delivered_revealed_shares
            if len(missing_shares):
                logger.warning(f"missing revealed shares from peer {from_id} ({missing_shares=})")
                for missing_idx in missing_shares:
                    # append invalid shares, just so that validation fails
                    self.revealed_shares[from_id].append((missing_idx, 0, 0))
            self.received_revealed_shares_from[from_id].set_result(True)
        elif "A" in msg.keys():
            await self.sent_extraction_commitments
            self.extraction_commitments[from_id] = msg["A"]
            if self.has_received_all_extraction_commitments():
                logger.debug(f"Received all extraction commitments.")
                self.received_all_extraction_commitments.set_result(True)
        elif "save" in msg.keys():
            logger.debug(f"Received save notification.")
            self.save(msg["save"])
        elif {"p", "g", "h", "t"} <= msg.keys():
            pass
        else:
            logger.error(f"Unknown message ({msg=})")

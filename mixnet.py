import asyncio
import json
import logging
import math
from typing import Dict, List, Tuple, Optional
from enum import Enum
from gmpy2 import mpz

import protocols
import settings
import shuffle
from measurement import measure_future
from elgamal import ElGamalKeypair, ElGamalCiphertext
from dkg import DistributedKeyGeneration
from integer import SchnorrGroup, IntJSONEncoder

logger = logging.getLogger(__name__)


class MixnetState(protocols.ProtocolState):

    class Status(Enum):
        # no DKG has been performed yet
        INIT = 0
        # DKG has been performed, users may register
        REGISTER = 1
        # permutation commitment has been computed, registration closed
        READY = 2
        # mixing has finalized, ready to decrypt
        MIXED = 4
        # threshold decryption done, result available
        DONE = 5

        def __str__(self):
            return self._name_

    def __init__(self, tid: str) -> None:
        super().__init__(tid)

        # need at least 3 mix peers for a mixing
        assert settings.NUM_PEERS >= 3

        self.status = self.Status.INIT

        self.p = settings.p
        self.g = settings.g
        self.h = settings.h
        self.G_q = SchnorrGroup(self.p)
        # public key not set (yet)
        self.y = None
        # DKG protocol instance (required for threshold decryption)
        self.dkg: Optional[DistributedKeyGeneration] = None
        self.consortium_pk = ElGamalKeypair.load("consortium/pk.json")

        self.psi = None
        self.h_i = None

        self.c = None
        self.r = None

        self.cond_new_user_added = asyncio.Condition()

        self.future_dkg_completed = asyncio.Future()
        self.futures_received_all_commitments = [asyncio.Future() for _ in range(settings.NUM_PEERS)]
        self.future_verified_all_commitments = asyncio.Future()
        self.future_wait_for_our_turn = asyncio.Future()
        self.future_all_peers_mixed = asyncio.Future()
        self.future_sent_decryption_shares = asyncio.Future()
        self.future_received_all_decryption_shares = asyncio.Future()

        self.users = []
        self.commitments = {}
        self.inverse_commitments = {}
        self.commitment_escrow_proofs = {}
        self.inverse_commitment_proofs = {}
        self.outputs = {}
        self.decryption_shares: List[Dict[int, mpz]] = []

    def info(self) -> Dict:
        return {
            "status": str(self.status),
            # explicitly encode as str instead of mpz (which is converted to int), becasue we may use this in
            # JavaScript code in the future
            "p": str(self.p),
            "g": str(self.g),
            "y": str(self.y),
            "numpeers": settings.NUM_PEERS,
            "numusers": len(self.users),
        }

    async def perform_keygen(self) -> None:
        assert self.status == self.Status.INIT

        self.dkg = DistributedKeyGeneration.init_new()
        self.dkg.set_params(
            self.G_q,
            self.g,
            self.h,
            math.ceil(settings.NUM_PEERS / 2 - 1)
        )

        # announce this DKG protocol instance
        msg = self.base_msg()
        msg["keygen_tid"] = self.dkg.transaction_id
        await self.send_msg(self.ALL_PEERS, msg)

        await self.dkg.perform()
        assert len(self.dkg.qual) >= 3

        self.y = self.dkg.y
        self.status = self.Status.REGISTER

        self.future_dkg_completed.set_result(True)

    def add_user(self, a: mpz, b: mpz) -> None:
        assert self.status == self.Status.REGISTER
        assert len(self.users) < settings.max_n

        self.users.append((a, b))

        # always have the right number of h_i generators ready
        # for the current number of users
        self.h_i = settings.h_i[0:len(self.users)]

    async def perform_register(self, a: mpz, b: mpz) -> None:
        assert self.status == self.Status.REGISTER

        self.add_user(a, b)
        if self.cond_new_user_added.locked():
            self.cond_new_user_added.notify_all()

        # broadcast new user to other peers
        msg = self.base_msg()
        msg["user_a"] = a
        msg["user_b"] = b
        await self.send_msg(self.dkg.qual_without_self, msg)

    async def commit(self) -> None:
        n = len(self.users)
        # generate random permutation
        self.psi = shuffle.get_random_permutation(n)
        logger.debug(f"Created random permutation of length {n}: {self.psi}")

        # generate commitment
        self.c, self.r = shuffle.generate_permutation_commitment(self.G_q, self.g, self.h_i, self.psi)

        if not settings.SINGLE_RECOVERY:
            # escrow permutation and prove consistency with commitment
            proof = shuffle.escrow_commitment(self.consortium_pk, self.g, self.h_i, self.c, self.r, self.psi)
        else:
            # single recovery mode: escrow inverse permutation
            psi_inv = shuffle.invert_permutation(self.psi)
            c_inv, r_inv = shuffle.generate_permutation_commitment(self.G_q, self.g, self.h_i, psi_inv)
            proof = shuffle.escrow_commitment(self.consortium_pk, self.g, self.h_i, c_inv, r_inv, psi_inv)
            proof_of_inversion = shuffle.proof_of_inverse_permutation_commitment(
                self.consortium_pk, self.c, c_inv, self.r, r_inv, self.psi, psi_inv
            )

        # helper function to serialize the lists of ElGamalCiphertext objects
        def serialize_ciphertext(c: List[ElGamalCiphertext]) -> List[Tuple[mpz, mpz]]:
            return [(ciphertext.a, ciphertext.b) for ciphertext in c]

        # for now, store data sent to consortium on disk
        Y: List[ElGamalCiphertext] = proof[2]
        consortium_data = serialize_ciphertext(Y)
        with open(f"consortium/permutation.{settings.PEER_ID}.json", mode="w+") as fp:
            json.dump(consortium_data, fp, cls=IntJSONEncoder)

        # broadcast commitment & proof of correct escrow
        msg = self.base_msg()
        msg["commitment"] = self.c
        msg["proof"] = serialize_ciphertext(proof[0]), serialize_ciphertext(proof[1]), serialize_ciphertext(
            proof[2]), proof[3], proof[4], proof[5], proof[6]
        if settings.SINGLE_RECOVERY:
            msg["inverse_commitment"] = c_inv
            msg["proof_of_inversion"] = (
                serialize_ciphertext(proof_of_inversion[0]),
                serialize_ciphertext(proof_of_inversion[1]),
                serialize_ciphertext(proof_of_inversion[2]),
                proof_of_inversion[3], proof_of_inversion[4], proof_of_inversion[5]
            )

        await self.send_msg(self.dkg.qual_without_self, msg)

        self.futures_received_all_commitments[settings.PEER_ID].set_result(True)

        # we do not wait for commitments from peers disqualified during DKG
        for i in set(settings.all_peer_ids()) - set(self.dkg.qual_without_self):
            self.futures_received_all_commitments[i].set_result(True)

        await measure_future(
            "future_received_all_commitments",
            asyncio.gather(*self.futures_received_all_commitments)
        )

        logger.info(f"Received all commitments, beginning verification of escrows ...")

        # verify all received commitments
        # helper function to deserialize the lists of ElGamalCiphertext objects
        def deserialize_ciphertext(c: List[List[mpz]]) -> List[ElGamalCiphertext]:
            return [ElGamalCiphertext(self.consortium_pk.G_q, lst[0], lst[1]) for lst in c]
        for pid in self.dkg.qual_without_self:
            commitment = self.commitments[pid]
            _proof = self.commitment_escrow_proofs[pid]

            proof = deserialize_ciphertext(_proof[0]), deserialize_ciphertext(_proof[1]), deserialize_ciphertext(
                _proof[2]), _proof[3], _proof[4], _proof[5], _proof[6]

            if not settings.SINGLE_RECOVERY:
                assert shuffle.verify_escrowed_commitment(proof, self.consortium_pk, self.g, self.h_i,
                                                          commitment)
            else:
                inverse_commitment = self.inverse_commitments[pid]
                assert shuffle.verify_escrowed_commitment(proof, self.consortium_pk, self.g, self.h_i,
                                                          inverse_commitment)
                _proof_of_inversion = self.inverse_commitment_proofs[pid]
                proof_of_inversion = (
                    deserialize_ciphertext(_proof_of_inversion[0]),
                    deserialize_ciphertext(_proof_of_inversion[1]),
                    deserialize_ciphertext(_proof_of_inversion[2]),
                    _proof_of_inversion[3], _proof_of_inversion[4], _proof_of_inversion[5]
                )
                assert shuffle.verify_inverse_permutation_commitment_proof(
                    proof_of_inversion, self.consortium_pk, commitment, inverse_commitment
                )
                logger.info(f"Verification of inverse permutation commitment completed!")

        logger.info(f"Verification of escrows completed!")

        self.status = self.Status.READY
        self.future_verified_all_commitments.set_result(True)

    async def perform_commit(self) -> None:
        msg = self.base_msg()
        msg["commit"] = True
        # tell the other peers how many users they should expect
        # before starting commitment phase (in case a register message
        # is delayed and arrives after the commit message)
        msg["numusers"] = len(self.users)
        await self.send_msg(self.dkg.qual_without_self, msg)

        await self.commit()

    @property
    def mixing_order(self) -> List[int]:
        return sorted(self.dkg.qual)

    async def mix(self) -> None:
        # first, wait for our turn (unless we are the first peer to mix)
        if settings.PEER_ID != self.mixing_order[0]:
            await measure_future("future_wait_for_our_turn", self.future_wait_for_our_turn)
        prev = self.outputs[max(self.outputs.keys())] if settings.PEER_ID != self.mixing_order[0] else self.users

        # instantiate ElGamal keypair object
        key = ElGamalKeypair.construct(self.p, self.g, self.y)
        # convert pairs of a, b to ElGamalCiphertext objects
        prev = [ElGamalCiphertext(self.G_q, a, b) for a, b in prev]
        # perform shuffle and store output and randomness used in re-encryption
        output, randomness, _ = shuffle.perform_random_shuffle(prev, key, self.psi)

        # perform Wikströms Proof of Shuffle
        proof = shuffle.proof_of_shuffle_wikstroem(
            self.G_q,
            self.g, self.h, self.h_i, prev, output, randomness, self.psi, self.c, self.r, key
        )

        # broadcast the outputs of our permutation as well as the TID of the proof protocol
        msg = self.base_msg()
        msg["proof"] = proof
        self.outputs[settings.PEER_ID] = [(ciphertext.a, ciphertext.b) for ciphertext in output]
        msg["output"] = self.outputs[settings.PEER_ID]
        await self.send_msg(self.dkg.qual_without_self, msg)

        # if we are the last peer, all peers have mixed
        if settings.PEER_ID == self.mixing_order[-1]:
            self.status = self.Status.MIXED
            self.future_all_peers_mixed.set_result(True)

    async def perform(self) -> None:
        assert self.status == self.Status.READY

        # tell all peers that we intend to start the mixing phase
        msg = self.base_msg()
        msg["invoke_mix"] = True
        await self.send_msg(self.dkg.qual_without_self, msg)

        # invoke local mixing, i.e. wait for our turn
        await self.mix()
        await measure_future("future_all_peers_mixed", self.future_all_peers_mixed)

    async def perform_decryption_share_pooling(self, c: List[ElGamalCiphertext]):
        if not len(self.decryption_shares):
            self.decryption_shares = [{} for _ in self.users]

        decryption_shares = [self.dkg.gen_decryption_share(_c) for _c in c]
        for d, s in zip(self.decryption_shares, decryption_shares):
            d.update(s)

        msg = self.base_msg()
        msg["decryption_shares"] = decryption_shares
        await self.send_msg(self.dkg.qual_without_self, msg)

        self.future_sent_decryption_shares.set_result(True)

    async def perform_threshold_decryption(self, c: List[ElGamalCiphertext]) -> None:
        await measure_future("future_received_all_decryption_shares", self.future_received_all_decryption_shares)

        decrypted = [self.dkg.combine_decryption_shares(c[i], self.decryption_shares[i]) for i in
                     range(len(self.users))]
        decoded = [self.G_q.decode(plaintext) for plaintext in decrypted]
        logger.info(f"Decrypted and decoded output: {decoded}")

    async def decrypt(self) -> None:
        logger.debug(f"Original input: {self.users}")
        output = self.outputs[self.mixing_order[-1]]
        logger.debug(f"Final output: {output}")

        ciphertexts = [ElGamalCiphertext(self.G_q, a, b) for a, b in output]

        # pool decryption shares
        await self.perform_decryption_share_pooling(ciphertexts)
        await self.perform_threshold_decryption(ciphertexts)

        self.status = self.Status.DONE

    async def perform_decrypt(self) -> None:
        assert self.status == self.Status.MIXED

        # tell all peers that we intend to start the mixing phase
        msg = self.base_msg()
        msg["invoke_decrypt"] = True
        await self.send_msg(self.dkg.qual_without_self, msg)

        await self.decrypt()

    async def process(self, msg: Dict) -> None:
        if "keygen_tid" in msg:
            assert self.status == self.Status.INIT

            keygen_tid = msg["keygen_tid"]
            logger.debug(f"waiting for protocol creation of {keygen_tid=} ...")
            await protocols.wait_for_protocol_creation(keygen_tid)
            self.dkg = protocols.transaction_manager[keygen_tid]
            # this just gets rid of linter warnings ...
            assert isinstance(self.dkg, DistributedKeyGeneration)

            logger.debug(f"waiting for protocol completion of {keygen_tid=} ...")
            await self.dkg.done

            assert len(self.dkg.qual) >= 3

            self.y = self.dkg.y
            logger.debug(f"registered public key {self.y=}")

            self.status = self.Status.REGISTER
            self.future_dkg_completed.set_result(True)
        elif {"user_a", "user_b"} <= msg.keys():
            await measure_future("future_dkg_completed", self.future_dkg_completed)
            assert self.status == self.Status.REGISTER
            logger.debug(f"Received user input from other peer: {(msg['user_a'], msg['user_b'])}")
            self.add_user(msg["user_a"], msg["user_b"])
        elif {"commit", "numusers"} <= msg.keys():
            # wait until we have received all remaining user registrations
            numusers = msg["numusers"]
            async with self.cond_new_user_added:
                await self.cond_new_user_added.wait_for(lambda: len(self.users) == numusers)
                logger.info(f"User registration complete.")

            await self.commit()
        elif {"commitment", "proof"} <= msg.keys():
            # we received a commitment from another peer
            logger.debug(f"Received commitment from peer {msg['from_id']} ({msg['commitment']}")
            logger.debug(f"Received proof of commitment escrow: {msg['proof']}")

            self.commitments[int(msg["from_id"])] = msg["commitment"]
            self.commitment_escrow_proofs[int(msg["from_id"])] = msg["proof"]

            if settings.SINGLE_RECOVERY:
                self.inverse_commitments[(int(msg["from_id"]))] = msg["inverse_commitment"]
                self.inverse_commitment_proofs[(int(msg["from_id"]))] = msg["proof_of_inversion"]

            self.futures_received_all_commitments[int(msg["from_id"])].set_result(True)
        elif "invoke_mix" in msg:
            await measure_future("future_verified_all_commitments", self.future_verified_all_commitments)
            assert self.status == self.Status.READY
            # this is the signal to start the mixing phase
            await self.mix()
        elif {"output", "proof"} <= msg.keys():
            # some peer mixed and sent us their re-encrypted output + a commitment consistent proof
            logger.debug(f"Received outputs from {msg['from_id']} = {msg['output']}")
            # TODO: check that the correct peer mixed, i.e., from_id == prev_id + 1 (or from_id == 0)
            # TODO: if a later proof arrives before an earlier one, we should wait for the earlier one to arrive
            proof = msg["proof"]

            prev = self.outputs[max(self.outputs.keys())] if int(msg["from_id"]) != self.mixing_order[0] else self.users

            # instantiate ElGamal keypair object
            key = ElGamalKeypair.construct(self.p, self.g, self.y)

            assert shuffle.verify_proof_of_shuffle_wikstroem(
                proof,
                self.G_q,
                self.g,
                self.h,
                self.h_i,
                key,
                prev,
                msg["output"], self.commitments[int(msg["from_id"])]
            )

            logger.debug(f"Shuffle proof from peer {msg['from_id']} accepted.")

            self.outputs[int(msg["from_id"])] = msg["output"]

            if self.mixing_order.index(msg["from_id"]) == self.mixing_order.index(settings.PEER_ID) - 1:
                self.future_wait_for_our_turn.set_result(True)

            if len(self.outputs.keys()) == len(self.dkg.qual):
                logger.debug(f"Looks like all peers have mixed, switching state.")
                self.status = self.Status.MIXED
                self.future_all_peers_mixed.set_result(True)
        elif "invoke_decrypt" in msg:
            await measure_future("future_all_peers_mixed", self.future_all_peers_mixed)
            assert self.status == self.Status.MIXED
            logger.info(f"Beginning decryption state")
            # this is the signal to start the threshold decryption phase
            await self.decrypt()
        elif "decryption_shares" in msg:
            await measure_future("future_sent_decryption_shares", self.future_sent_decryption_shares)

            logger.debug(f"received decryption shares:  {msg['decryption_shares']}")

            if not len(self.decryption_shares):
                self.decryption_shares = [{} for _ in self.users]

            # typecast keys of the individual dicts to int
            decryption_shares = [{int(k): v for k, v in d.items()} for d in msg["decryption_shares"]]
            for d, s in zip(self.decryption_shares, decryption_shares):
                d.update(s)

            logger.debug(f"updated decryption shares: {self.decryption_shares}")
            if all(len(d.keys()) == len(self.dkg.qual) for d in self.decryption_shares):
                logger.info(f"received all decryption shares!")
                self.future_received_all_decryption_shares.set_result(True)
        else:
            logger.error(f"Unrecognized packet: {msg}")

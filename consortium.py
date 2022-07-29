import asyncio
import logging
import json
import re
from abc import ABC
from typing import Dict, List
from pathlib import Path
from gmpy2 import mpz

import measurement
import settings
import protocols
import dkg
from dkg import DecryptionShare
import elgamal
import shuffle
from integer import IntJSONDecoder

logger = logging.getLogger(__name__)


class ConsortiumState(protocols.ProtocolState, ABC):

    def __init__(self, tid: str) -> None:
        super().__init__(tid)

        self.mixpeers: List[int] = []
        for file in Path("consortium/").iterdir():
            pattern = re.compile(r"permutation\.(?P<peer_id>[0-9]+)\.json")
            match = pattern.fullmatch(file.name)
            if match:
                self.mixpeers.append(int(match.group("peer_id")))
        self.mixpeers = sorted(self.mixpeers)
        logger.info(f"Found escrowed permutations by mixpeers {self.mixpeers}")

        self.permutations: Dict[int, List[elgamal.ElGamalCiphertext]] = {}

        # load DKG information for decryption
        self.dkg = dkg.DistributedKeyGeneration.load(f"consortium/dkg.{settings.PEER_ID}.json")

        # load encrypted permutation ciphertexts
        for i in self.mixpeers:
            with open(f"consortium/permutation.{i}.json", mode="r") as fp:
                data = json.load(fp, cls=IntJSONDecoder)
            self.permutations[i] = [
                elgamal.ElGamalCiphertext(self.dkg.G_q, c[0], c[1])
                for c in data
            ]

        self.received_all_decryption_shares = asyncio.Future()


class ConsortiumStateFullRecovery(ConsortiumState):

    def __init__(self, tid: str) -> None:
        super().__init__(tid)

        self.decryption_shares: List[List[Dict[int, DecryptionShare]]] = []

    def add_decryption_shares(self, shares: List[List[Dict[int, mpz]]]):
        if not self.decryption_shares:
            # number of users that participated, i.e. length of permutations
            numusers = len(self.permutations[0])
            # initialize data structure for decryption shares
            self.decryption_shares = [[dict() for _ in range(numusers)] for _ in self.mixpeers]

        # update the dicts to add new decryption shares
        for d, s in zip(self.decryption_shares, shares):
            for di, si in zip(d, s):
                di.update(si)

        # check whether all shares have been received
        shares_complete = all(all(len(di) == len(self.dkg.qual) for di in d) for d in self.decryption_shares)
        if shares_complete:
            logger.debug(f"shares complete!")
            self.received_all_decryption_shares.set_result(True)

    @measurement.measure_async("recover")
    async def recover(self):
        # generate decryption shares for all ciphertexts
        permutations = [value for (key, value) in sorted(self.permutations.items(), key=lambda x: x[0])]
        shares = [[self.dkg.gen_decryption_share(c) for c in p] for p in permutations]
        # update our local storage of decryption shares with our own
        self.add_decryption_shares(shares)

        # broadcast our shares to the other peers
        msg = self.base_msg()
        msg["shares"] = shares
        logger.debug(f"shares: {shares}")
        await self.send_msg(self.dkg.qual_without_self, msg)

        # wait until we have received all shares
        await self.received_all_decryption_shares

        # combine all shares to receive plaintexts
        decrypted: List[List[mpz]] = [[self.dkg.combine_decryption_shares(c, shares) for c, shares in zip(p, s)]
                                      for p, s in zip(permutations, self.decryption_shares)]

        numusers = len(self.permutations[0])
        h_i = settings.h_i[0:numusers]
        permutations_clear = [shuffle.extract_escrowed_permutation_decrypted(y, h_i) for y in decrypted]
        logger.debug(f"Cleartext permutations = {permutations_clear}")

        # obtain the total permutation for identity recovery
        psi = shuffle.concatenate_permutations(permutations_clear)
        logger.info(f"Final permutation = {psi}")

    async def perform(self) -> None:
        msg = self.base_msg()
        msg["recover"] = True
        await self.send_msg(self.dkg.qual_without_self, msg)
        await self.recover()

    async def process(self, msg: Dict) -> None:
        if "recover" in msg:
            await self.recover()
        if "shares" in msg:
            shares = msg["shares"]
            logger.debug(f"Received shares from peer {msg['from_id']}: {shares}")
            self.add_decryption_shares(shares)


class ConsortiumStateSingleRecovery(ConsortiumState):

    def __init__(self, tid: str) -> None:
        super().__init__(tid)
        self.u: int = -1

        self.decryption_shares: Dict[int, Dict[int, DecryptionShare]] = {i: dict() for i in self.mixpeers}
        self.received_shares_for_mix_peer: List[asyncio.Future] = [asyncio.Future() for _ in self.mixpeers]

    def set_output_index(self, u: int) -> None:
        self.u = u

    def add_decryption_share(self, i: int, share: Dict[int, DecryptionShare]) -> None:
        self.decryption_shares[i].update(share)
        if len(self.decryption_shares[i].keys()) == settings.NUM_PEERS:
            self.received_shares_for_mix_peer[i].set_result(True)

    @measurement.measure_async("recover_single")
    async def recover(self):
        assert self.u >= 0

        numusers = len(self.permutations[0])
        h_i = settings.h_i[0:numusers]

        u = self.u
        for i in reversed(self.mixpeers):
            y_u = self.permutations[i][u]
            share = self.dkg.gen_decryption_share(y_u)

            self.add_decryption_share(i, share)

            # broadcast our share to the other peers
            msg = self.base_msg()
            msg["share"] = share
            msg["i"] = i
            await self.send_msg(self.dkg.qual_without_self, msg)

            await self.received_shares_for_mix_peer[i]

            decrypted = self.dkg.combine_decryption_shares(y_u, self.decryption_shares[i])
            u_prime = h_i.index(decrypted)
            u = u_prime
        logger.info(f"Recovered identity for output {self.u}: User {u}")

    async def perform(self) -> None:
        msg = self.base_msg()
        msg["recover"] = self.u
        await self.send_msg(self.dkg.qual_without_self, msg)
        await self.recover()

    async def process(self, msg: Dict) -> None:
        if "recover" in msg:
            self.set_output_index(msg["recover"])
            await self.recover()
        if "share" in msg:
            self.add_decryption_share(msg["i"], msg["share"])

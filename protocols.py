import os
import sys
import logging
import asyncio
import json
import inspect
import hashlib
from typing import Dict, Type, Union, List
from abc import ABC, abstractmethod
from gmpy2 import mpz
from aiohttp import ClientTimeout
from aiohttp_retry import RetryClient, ExponentialRetry

import settings
from integer import IntJSONEncoder

_next_transaction_id: int = int.from_bytes(os.urandom(8), sys.byteorder)

logger = logging.getLogger(__name__)


def next_transaction_id() -> str:
    global _next_transaction_id

    tid = _next_transaction_id
    _next_transaction_id += 1
    return f"TID{settings.PEER_ID}_{tid}"


transaction_manager: Dict[str, "ProtocolState"] = {}
protocol_creation_futures: Dict[str, asyncio.Future] = {}


async def wait_for_protocol_creation(tid: str) -> None:
    """
    Waits for a protocol state to be created with the specified transaction id.
    :param tid: The transaction id to wait for
    """
    if tid in transaction_manager:
        return
    protocol_creation_futures[tid] = asyncio.Future()
    await protocol_creation_futures[tid]


class ProtocolState(ABC):
    ALL_PEERS = -1

    def __init__(self, tid: str) -> None:
        self.tid = tid

    @classmethod
    def init_from_msg(cls, msg: Dict) -> "ProtocolState":
        """
        Processes a received message and returns a matching ProtocolState object.
        In case the transaction_manager does not contain an existing state object for the
        transaction id specified in the message, a new state object will be created.
        :param msg: The received message (a Dict parsed from JSON).
        :return: The correct state object (a subclass of ProtocolState)
        """
        ProtocolState.verify_msg(msg)

        protocol: Type["ProtocolState"] = getattr(sys.modules[msg["module"]], msg["protocol"])
        tid = msg["tid"]
        if tid in transaction_manager:
            return transaction_manager[tid]
        logger.debug(f"Creating new protocol state (tid={tid})")
        transaction_manager[tid] = protocol(tid)
        # notify anyone waiting for the creation of this protocol state
        if tid in protocol_creation_futures:
            logger.debug(f"Notifying protocol creation future (tid={tid})")
            protocol_creation_futures[tid].set_result(True)
        return transaction_manager[tid]

    @classmethod
    def init_new(cls) -> "ProtocolState":
        """
        Initializes a new instance of this protocol by generating a new transaction id and a fresh state object.
        :return: A fresh state object using a new, unique transaction id.
        """
        tid = next_transaction_id()
        transaction_manager[tid] = cls(tid)
        return transaction_manager[tid]

    @property
    def transaction_id(self) -> str:
        """
        Returns a unique transaction id associated with the instance of this protocol execution.
        :return: The unique transaction id for this state object.
        """
        return self.tid

    def base_msg(self) -> Dict:
        return {
            "module": inspect.getmodule(self).__name__,
            "protocol": type(self).__name__,
            "tid": self.transaction_id,
            "from_id": settings.PEER_ID
        }

    @staticmethod
    def hash_msg(msg: Dict) -> mpz:
        h = hashlib.sha256()
        for k, v in msg.items():
            if isinstance(v, str):
                h.update(k.encode())
            if isinstance(v, int):
                v = mpz(v)
            if isinstance(v, type(mpz())):
                h.update(v.digits().encode())
        c = mpz(int.from_bytes(bytes=h.digest(), byteorder='little')) % settings.ELGAMAL_KEYS[0].G_q.p
        return settings.ELGAMAL_KEYS[0].G_q.encode(c)

    @staticmethod
    def sign_msg(msg: Dict) -> None:
        """
        Signs the message object (passed as a reference) using the private elgamal key of this peer.
        :param msg: Message dict
        """
        h = ProtocolState.hash_msg(msg)
        a, b = settings.ELGAMAL_KEYS[settings.PEER_ID].sign(h)
        msg["sign_a"] = a
        msg["sign_b"] = b

    @staticmethod
    def verify_msg(msg: Dict) -> None:
        """
        Verify the signature of the received message. Aborts with an AssertionError if a signature is incorrect.
        :param msg: Received message dict
        """
        a, b = msg["sign_a"], msg["sign_b"]

        del msg["sign_a"]
        del msg["sign_b"]

        h = ProtocolState.hash_msg(msg)
        assert settings.ELGAMAL_KEYS[msg["from_id"]].verify(h, (a, b))

    @staticmethod
    async def send_msg(peer: Union[int, List[int]], msg: Dict) -> None:
        """
        JSON-encodes the msg-Dict and sends it to the specified peer. If the given peer id is less than zero,
        the message is broadcasted to all peers.
        :param peer: Peer-id of the recipient, or any negative integer in case of a broadcast.
        :param msg: A python dictionary containing the message.
        """
        if isinstance(peer, int):
            if peer < 0:
                peer = settings.all_peer_ids()
            else:
                peer = [peer]
        ports = [settings.peer_port(pid) for pid in peer]

        ProtocolState.sign_msg(msg)

        data = json.dumps(msg, cls=IntJSONEncoder)
        async with RetryClient(retry_options=ExponentialRetry(attempts=10), timeout=ClientTimeout()) as client:
            await asyncio.wait([
                client.post(f"http://127.0.0.1:{port}/peer", data=data)
                for port in ports
            ])

    @abstractmethod
    async def perform(self) -> None:
        """
        Begins the execution of the protocol.
        """
        raise NotImplementedError

    @abstractmethod
    async def process(self, msg: Dict) -> None:
        """
        Processes a received msg related to this protocol and progresses the protocol execution.
        :param msg: The received message (a Dict parsed from JSON).
        """
        raise NotImplementedError

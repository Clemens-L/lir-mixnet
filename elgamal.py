import logging
import os
import json
from pathlib import Path
from gmpy2 import mpz, invert, gcd
from typing import Tuple

from integer import SchnorrGroup, IntegerRandfunc, random_integer, IntJSONEncoder, IntJSONDecoder

logger = logging.getLogger(__name__)


class ElGamalCiphertext(object):
    """
    Represents a ciphertext (a, b) from G_q x G_q in the ElGamal encryption scheme.
    Can be multiplied with other ElGamalCiphertext objects to exploit the homomorphic properties of ElGamal.
    """
    def __init__(self, G_q: SchnorrGroup, a: mpz, b: mpz):
        assert G_q.is_element(a)
        assert G_q.is_element(b)

        self.G_q = G_q
        self.a = a
        self.b = b

    def __mul__(self, other: "ElGamalCiphertext") -> "ElGamalCiphertext":
        assert self.G_q == other.G_q
        return ElGamalCiphertext(
            self.G_q,
            (self.a * other.a) % self.G_q.p,
            (self.b * other.b) % self.G_q.p
        )

    def __repr__(self):
        return f"ElGamalCiphertext(a={self.a}, b={self.b})"


class ElGamalKeypair(object):
    """
    Represents an ElGamal keypair and implements methods for encryption and decryption, as well as
    generation of keypairs.
    The secret key can be omitted, in cases where it is unknown. (Decryption will not work in those cases).
    """
    @classmethod
    def generate(cls, p: mpz, g: mpz = None, randfunc:IntegerRandfunc = None) -> "ElGamalKeypair":
        """
        Generates a new ElGamal keypair.
        :param p: A safe prime (i.e. a prime such that (p-1)/2 is also prime)
        :param randfunc: Optionally, a random number generator of the signature rng(min_inclusive, max_exclusive)
        :return: An ElGamalKeypair-object.
        """
        keypair = cls(randfunc=randfunc)
        keypair.G_q = SchnorrGroup(p)

        if not g:
            g = keypair.G_q.get_random_generator()
        keypair.g = g

        # secret key in Z_q = [2 .. q-1]
        keypair.x = keypair.randfunc(2, keypair.G_q.order())

        keypair.y = keypair.G_q.powmod(keypair.g, keypair.x)

        return keypair

    @classmethod
    def construct(cls, p: mpz, g: mpz, y: mpz, x: mpz = None, randfunc: IntegerRandfunc = None) -> "ElGamalKeypair":
        """
        Constructs an ElGamalKeypair-object from known values.
        :param p: A safe prime.
        :param g: A generator of the group G_q (q = (p-1)/2)
        :param y: The public key
        :param x: The private key
        :param randfunc: Optionally, a random number generator of the signature rng(min_inclusive, max_exclusive)
        :return: An ElGamalKeypair-object.
        """
        keypair = cls(randfunc=randfunc)
        keypair.G_q = SchnorrGroup(p)

        keypair.g = g
        keypair.y = y
        keypair.x = x

        if x:
            assert keypair.G_q.powmod(g, x) == y

        return keypair

    def __init__(self, randfunc: IntegerRandfunc = None):
        if not randfunc:
            randfunc = random_integer
        self.randfunc = randfunc

        self.G_q: SchnorrGroup = None
        self.g: mpz = None
        self.y: mpz = None
        self.x: mpz = None

    def only_public(self) -> "ElGamalKeypair":
        """
        Returns a keypair without the private key (if present).
        Returns this keypair if there was no private key to begin with.
        :return: An ElGamalKeypair object with no private key.
        """
        if not self.x:
            return self
        return ElGamalKeypair.construct(self.G_q.p, self.g, self.y, randfunc=self.randfunc)

    @classmethod
    def load(cls, filename: str) -> "ElGamalKeypair":
        """
        Initializes an ElGamalKeypair object from values saved to a JSON-file.
        :param filename: The path to the JSON-file.
        :return: An ElGamalKeypair object.
        """
        with open(filename, mode="r") as fp:
            data = json.load(fp, cls=IntJSONDecoder)

        return cls.construct(data["p"], data["g"], data["y"], data["x"] if "x" in data else None)

    def save(self, filename: str) -> None:
        """
        Writes the parameters of this ElGamalKeypair to a JSON-file.
        :param filename: The path to the JSON-file.
        """
        data = {
            "p": self.G_q.p,
            "g": self.g,
            "y": self.y,
            "x": self.x,
        }

        Path(os.path.dirname(filename)).mkdir(parents=True, exist_ok=True)
        with open(filename, mode="w+") as fp:
            json.dump(data, fp, cls=IntJSONEncoder)

    def get_randomness(self) -> mpz:
        """
        Returns a suitable randomness from Z_q = [0 .. q-1], q order of G_q
        :return: An integer.
        """
        return self.randfunc(0, self.G_q.order())

    def encrypt(self, m: mpz, r: mpz = None) -> ElGamalCiphertext:
        """
        Encrypts a plaintext using the public key of this keypair.
        :param m: A plaintext (which must be an element of G_q).
        :param r: Optionally, the randomness to use.
        :return: An ElGamalCiphertext object.
        """
        assert self.G_q.is_element(m)

        # randomness in Z_q = [0 .. q-1]
        if not r:
            r = self.get_randomness()

        a = self.G_q.powmod(self.g, r)
        b = (m * self.G_q.powmod(self.y, r)) % self.G_q.p

        return ElGamalCiphertext(self.G_q, a, b)

    def decrypt(self, c: ElGamalCiphertext) -> mpz:
        """
        Decrypts a given ciphertext using the private key of this keypair. (Must be present!)
        :param c: An ElGamalCiphertext object.
        :return: The plaintext (element of G_q)
        """

        assert c.G_q == self.G_q

        # decryption only possible if private key is present
        assert self.x

        m = (c.b * self.G_q.powmod(invert(c.a, self.G_q.p), self.x)) % self.G_q.p

        assert self.G_q.is_element(m)

        return m

    def reblind(self, c: ElGamalCiphertext, r: mpz = None) -> ElGamalCiphertext:
        """
        "Reblinds" a given ciphertext by encrypting the neutral element 1 and multiplying both ciphertexts.
        :param c: An ElGamalCiphertext object.
        :param r: Optionally, the randomness to use when encrypting the neutral element.
        :return: A different ElGamalCiphertext object c' s.t. decrypt(c) == decrypt(c')
        """
        neutral = self.encrypt(mpz(1), r)
        return c * neutral

    def sign(self, m: mpz, k: mpz = None) -> Tuple[mpz, mpz]:
        """
        Signs a message m using the private key of this object and a random value k.
        k must be choosen s.t. 0 < k < p - 1 and gcd(k, p - 1) == 1
        Parameter k is optional and will be generated, if missing
        :param m: Message to be signed, element of this group
        :param k: Random value k
        :return: A signature (a, b)
        """
        p1 = self.G_q.p - 1
        if not k:
            k = random_integer(0, p1)
            while gcd(k, p1) > 1:
                k = random_integer(0, p1)
        assert gcd(k, p1) == 1

        a = self.G_q.powmod(self.g, k)
        t = (m - self.x * a) % p1
        while t < 0:
            t = t + p1
        b = t * invert(k, p1) % p1
        return a, b

    def verify(self, m: mpz, s: Tuple[mpz, mpz]) -> bool:
        """
        Verifies that the given signature matches message m, and was signed using this keypairs
        secret key.
        :param m: Message m
        :param s: A signate s = (a, b)
        :return: True, iff the verification was successful.
        """
        if not 0 < s[0] < self.G_q.p:
            return False
        v1 = self.G_q.powmod(self.y, s[0])
        v1 = v1 * self.G_q.powmod(s[0], s[1]) % self.G_q.p
        v2 = self.G_q.powmod(self.g, m)
        return v1 == v2

    def __repr__(self):
        return f"ElGamalKeyPair(p={self.G_q.p}, g={self.g}, y={self.y}, x={self.x})"

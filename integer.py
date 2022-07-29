import secrets
import gmpy2
from typing import Tuple, List, Iterator, Callable, Union, Any
from json import JSONEncoder, JSONDecoder
from gmpy2 import mpz, powmod

rng = secrets.SystemRandom()

Int = Union[int, mpz]
IntegerRandfunc = Callable[[Int, Int], Int]


def get_probable_prime(bits: int) -> mpz:
    """
    Returns a (probable) prime whose bitwise representation is of length 'bits'.
    :param bits: Length (in bits) of the generated prime.
    :return: A probable prime of length 'bits'
    """
    while 1:
        rand = mpz(rng.getrandbits(bits))
        if gmpy2.is_prime(rand):
            return rand


def get_probable_safe_prime(bits: int) -> Tuple[mpz, mpz]:
    """
    Returns a tuple of two (probable) primes p and q, where p = 2*q + 1 and the bitwise representation of p
    has length 'bits'.
    :param bits: Length (in bits) of the safe prime p.
    :return: Tuple (p, q) of probable primes, where p is a safe prime.
    """
    while 1:
        q = get_probable_prime(bits - 1)
        p = q * 2 + 1
        if p.bit_length() != bits:
            continue
        if gmpy2.is_prime(p):
            return p, q


def get_cunningham_chain(bits: int) -> Tuple[mpz, mpz, mpz]:
    """
    Returns a cunningham chain of length 3 of (probable) primes p, q and r, where p = 2*q + 1 and q = 2*r + 1,
    and the bitwise representation of p has length 'bits'.
    :param bits: Length (in bits) of the safe prime p.
    :return: Tuple (p, q, r) of probable primes, where p and q are safe primes and q and r are Sophie Germain primes.
    """
    while 1:
        # while we could use get_probable_safe_prime to obtain q and r, it could result in a few more prime checks
        # (in case the bit length of p is too small)
        r = get_probable_prime(bits - 2)
        q = r * 2 + 1
        if q.bit_length() != bits - 1:
            continue
        p = q * 2 + 1
        if p.bit_length() != bits:
            continue
        if gmpy2.is_prime(q) and gmpy2.is_prime(p):
            return p, q, r


def random_integer(min_inclusive: Int, max_exclusive: Int) -> Int:
    """
    Generates a random integer from the range [min_inclusive, max_exclusive).
    :param min_inclusive: Minimum value of the random number (inclusive)
    :param max_exclusive: Maximal value of the random number (exclusive)
    :return: A random integer.
    """
    return mpz(rng.randint(min_inclusive, max_exclusive - 1))


class IntJSONEncoder(JSONEncoder):
    """
    Simple JSONEncoder extension that supports storing mpz values as ints.
    """
    def default(self, o: Any) -> Any:
        if isinstance(o, type(mpz())):
            return int(o)
        return JSONEncoder.default(self, o)


class IntJSONDecoder(JSONDecoder):
    """
    Simple JSONDecoder extension that converts any int values as mpz.
    """

    def __init__(self):
        JSONDecoder.__init__(self, parse_int=self.convert_int_to_mpz)

    def convert_int_to_mpz(self, s: str):
        return mpz(s)


class SchnorrGroup(object):

    """
    An object representing a cyclic group of prime order q.
    The group is a subgroup of Z_p^x, where p is a safe prime.
    (see also: https://en.wikipedia.org/wiki/Schnorr_group)
    """

    @classmethod
    def generate_params(cls, bits: int) -> "SchnorrGroup":
        """
        Generates a safe prime p and returns a group object of the cyclic subgroup
        of prime order q.
        :param bits: Bitwise length of prime p.
        :return: A SchnorrGroup object.
        """
        return SchnorrGroup(get_probable_safe_prime(bits)[0])

    def __init__(self, p: mpz):
        self.p = p
        self.q = (p - 1) // 2

        # sanity checks on group parameters parameters
        assert gmpy2.is_prime(self.p)
        assert gmpy2.is_prime(self.q)

    def order(self) -> mpz:
        """
        Determines the order of this group.
        :return: The order of the group (as an integer).
        """
        return self.q

    def get_random_generator(self) -> mpz:
        """
        Find a random generator of this group.
        :return: A generator g of this group.
        """
        while 1:
            h = random_integer(2, self.p)
            g = powmod(h, 2, self.p)
            if g != 1:
                return g

    def is_element(self, x: mpz) -> bool:
        """
        Checks whether an integer x is element of this group.
        :param x: An integer.
        :return: True, iff x is element of this group..
        """
        return powmod(x, self.q, self.p) == 1

    def get_random_element(self) -> mpz:
        """
        Finds and returns a random element of this group.
        :return: An integer x such that is_element(x) is True.
        """
        while 1:
            x = random_integer(1, self.p)
            if self.is_element(x):
                return x

    def powmod(self, x: mpz, y: mpz, m: mpz = None) -> mpz:
        """
        Computes the power of two group elements modulo p: powmod(x, y, p).
        :param x: The base.
        :param y: The exponent.
        :param m: The modulus to use (default: self.p)
        :return: (x**y)%p
        """

        if not m:
            m = self.p

        assert self.is_element(x)

        return powmod(x, y, m)

    def enumerate(self) -> Iterator[mpz]:
        """
        Enumerates all elements in this group.
        For debugging reasons / testing only, works for small groups only.
        :return: A list of all group elements.
        """
        for i in range(1, self.p):
            if self.is_element(i):
                yield mpz(i)

    def encode(self, n: int) -> mpz:
        """
        Maps an integer in the range [0, q-2] to a group element.
        The mapping can be inverted using SchnorrGroup.decode().
        :param n: An integer in the range [0, q-2].
        :return: A group element.
        """

        # need to add 1, cannot encode zero directly
        m = mpz(n) + 1
        
        # self.q == number of elements
        # => we can encode positive numbers up to q-2
        assert m < self.q
        # cannot currently encode negative numbers this way
        assert m >= 0

        if self.is_element(m):
            return m

        return (-m) % self.p

    def decode(self, element: mpz) -> int:
        """
        Reverts the mapping of the SchnorrGroup.encode() function.
        Given a group element, an integer in the range [0, q-2] will be returned.
        :param element: A group element.
        :return: An integer in the range [0, q-2]
        """

        assert self.is_element(element)

        if element <= self.q:
            return int(element - 1)

        return int((-element) % self.p - 1)

    def __eq__(self, other):
        return self.p == other.p

    def __repr__(self):
        return f"SchnorrGroup(p={self.p}, q={self.q})"

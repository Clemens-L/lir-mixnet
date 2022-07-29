import random
import unittest
import logging

import integer
from integer import SchnorrGroup

logging.basicConfig(format='%(asctime)s %(module)s %(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


class IntegerGroupsTestCase(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()

        # pin seed
        integer.rng = random.Random(x=1)

        self.groups = [
            SchnorrGroup.generate_params(bits=16)
        ]

    def test_generator_generates_all_elements(self):
        """Tests whether a generator can actually be used to generate all group elements."""
        for G in self.groups:
            logger.info(f"Testing generators for group type {type(G)}")
            g = G.get_random_generator()

            elems = set(G.enumerate())
            num_elems = G.order()

            generated_elems = set()

            for k in range(1, G.order() + 1):
                a = G.powmod(g, k)
                generated_elems.add(a)

            self.assertEqual(elems, generated_elems)
            self.assertEqual(len(generated_elems), num_elems)

    def test_encode_decode(self):
        """Tests whether the encode & decode mappings are correct & the inversion of each other."""
        for G in self.groups:
            logger.info(f"Testing encode/decode for group type {type(G)}")
            # we should be able to encode all integers in [0, q - 2]
            valid_integers = range(0, G.q - 1)
            for i in valid_integers:
                elem = G.encode(i)
                # encoded value must be group element
                self.assertTrue(G.is_element(elem))
    
                decoded = G.decode(elem)
                # decoded value must match the initial value
                self.assertEqual(i, decoded)


if __name__ == '__main__':
    unittest.main()

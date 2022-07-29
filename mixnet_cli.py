import argparse
import logging
from typing import Dict, List
from gmpy2 import mpz

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from integer import SchnorrGroup
from elgamal import ElGamalKeypair

logger = logging.getLogger(__name__)
logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s %(module)s: %(message)s",
    )

# retry strategy for http requests to peers
retry_strategy = Retry(
    total=6,
    backoff_factor=1
)
adapter = HTTPAdapter(max_retries=retry_strategy)
http = requests.Session()
http.mount("http://", adapter)


def info(_: Dict) -> None:
    response = http.get("http://127.0.0.1:32768/mix/info")
    logger.info(response.text)


def keygen(_: Dict) -> None:
    logger.info(f"Starting keygen phase ...")
    response = http.post("http://127.0.0.1:32768/mix/keygen")
    logger.info(f"HTTP Response: {response}")


def register(args: Dict) -> None:
    logger.info(f"Submitting user inputs ...")
    input = mpz(args.get("input"))
    logger.info(f"User input: {input}")

    # build keypair
    info_obj = http.get("http://127.0.0.1:32768/mix/info").json()
    assert info_obj["status"] == "REGISTER"
    keypair = ElGamalKeypair.construct(mpz(info_obj["p"]), mpz(info_obj["g"]), mpz(info_obj["y"]))

    # instantiate group to encode user input (needs to be group element)
    G = SchnorrGroup(mpz(info_obj["p"]))
    elem = G.encode(input)
    logger.debug(f"Encoded user input: {elem}")

    # encrypt user input using public key
    ciphertext = keypair.encrypt(elem)
    logger.debug(f"Encrypted user input: {ciphertext}")

    response = http.post("http://127.0.0.1:32768/mix/register", json={
        "a": str(ciphertext.a),
        "b": str(ciphertext.b)
    })

    logger.info(f"HTTP Response: {response}")


def commit(_: Dict) -> None:
    logger.info(f"Starting commit phase ...")
    response = http.post("http://127.0.0.1:32768/mix/commit")
    logger.info(f"HTTP Response: {response}")


def perform(_: Dict) -> None:
    logger.info(f"Starting mixing phase ...")
    response = http.post("http://127.0.0.1:32768/mix/perform")
    logger.info(f"HTTP Response: {response}")


def decrypt(_: Dict) -> None:
    logger.info(f"Starting decryption phase ...")
    response = http.post("http://127.0.0.1:32768/mix/decrypt")
    logger.info(f"HTTP Response: {response}")


def recover(_: Dict) -> None:
    logger.info(f"Starting recovery phase ...")
    response = http.post("http://127.0.0.1:32768/consortium/recover")
    logger.info(f"HTTP Response: {response}")


def consortium_keygen(_: Dict) -> None:
    logger.info(f"Starting consortium keygen phase ...")
    response = http.post("http://127.0.0.1:32768/consortium/keygen")
    logger.info(f"HTTP Response: {response}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="Mixnet Command-Line Interface",
        description="Allows control of the mixnet, as well as submitting user inputs",
        add_help=True
    )
    parser.add_argument("action", nargs='?', type=str, default="start",
                        choices=["info", "keygen", "register", "commit", "perform", "decrypt", "recover",
                                 "consortium-keygen"])
    parser.add_argument("--input", required=False, type=str,
                        help="User input to mixing network.")
    parser.add_argument("--numpeers", required=False, type=int, help="Specify the number of peers whose permutation "
                                                                     "shall be recovered.")
    args = parser.parse_args()

    func = {
        "consortium-keygen": consortium_keygen,
        "info": info,
        "keygen": keygen,
        "register": register,
        "commit": commit,
        "perform": perform,
        "decrypt": decrypt,
        "recover": recover,
    }
    func[args.action](dict(args.__dict__))


if __name__ == '__main__':
    main()

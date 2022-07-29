import argparse
import logging
import json
import time
import hashlib
from typing import Dict, List
from tqdm import tqdm
from gmpy2 import mpz

import settings
from integer import SchnorrGroup, random_integer
from elgamal import ElGamalKeypair
from zkps import (
    proof_correct_decryption,
    verify_correct_decryption,
    proof_plaintext_equality_or,
    verify_plaintext_equality_or,
    proof_plaintext_dlog,
    verify_plaintext_dlog,
)

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s %(module)s: %(message)s",
)

benchmark_results: Dict[str, int] = {}


def benchmark_rng(args: Dict[str, any]) -> None:
    iterations = args["iterations"]

    durations: List[int] = []
    for _ in tqdm(range(iterations)):
        start = time.time_ns()
        random_integer(2, settings.q)
        stop = time.time_ns()
        durations.append(stop - start)

    average = sum(durations) // len(durations)
    logger.info(f"Benchmarking complete - average duration: {average} ns")
    benchmark_results["rng"] = average


def benchmark_powmod(args: Dict[str, any]) -> None:
    iterations = args["iterations"]

    def _random_element():
        z = 1
        while z == 1:
            z = G_q.get_random_element()
        return z

    G_q = SchnorrGroup(settings.p)
    x = _random_element()

    durations: List[int] = []
    for _ in tqdm(range(iterations)):
        y = random_integer(2, G_q.order())

        start = time.time_ns()
        x = G_q.powmod(x, y)
        stop = time.time_ns()
        durations.append(stop - start)

    average = sum(durations) // len(durations)
    logger.info(f"Benchmarking complete - average duration: {average} ns")
    benchmark_results["powmod"] = average


def benchmark_sha256(args: Dict[str, any]) -> None:
    iterations = args["iterations"]

    x = random_integer(0, settings.p)

    durations: List[int] = []
    for _ in tqdm(range(iterations)):
        h = hashlib.sha256()
        start = time.time_ns()
        h.update(x.digits().encode())
        x = mpz(int.from_bytes(bytes=h.digest(), byteorder="little"))
        stop = time.time_ns()
        durations.append(stop - start)

    average = sum(durations) // len(durations)
    logger.info(f"Benchmarking complete - average duration: {average} ns")
    benchmark_results["sha256"] = average


def benchmark_zkp_correct_decryption(args: Dict[str, any]) -> None:
    iterations = args["iterations"]

    key = ElGamalKeypair.generate(settings.p, settings.g)
    m = key.G_q.get_random_element()
    r = random_integer(0, key.G_q.order())
    c = key.encrypt(m, r)

    durations_proof: List[int] = []
    durations_verify: List[int] = []
    for _ in tqdm(range(iterations)):
        start = time.time_ns()
        proof = proof_correct_decryption(key, c, m, r)
        stop = time.time_ns()
        durations_proof.append(stop - start)

        start = time.time_ns()
        result = verify_correct_decryption(proof, key, c, m)
        stop = time.time_ns()
        durations_verify.append(stop - start)

        assert result

    average_proof = sum(durations_proof) // len(durations_proof)
    average_verify = sum(durations_verify) // len(durations_verify)

    logger.info(
        f"Benchmarking complete - average duration: {average_proof} ns for proof, {average_verify} for verify"
    )
    benchmark_results["correct_decryption_proof"] = average_proof
    benchmark_results["correct_decryption_verify"] = average_verify


def benchmark_zkp_plaintext_equality_or(args: Dict[str, any]) -> None:
    iterations = args["iterations"]
    n_alternatives = args["n_alternatives"]

    key = ElGamalKeypair.generate(settings.p, settings.g)
    m = key.G_q.get_random_element()
    r = random_integer(0, key.G_q.order())
    r_alt = random_integer(0, key.G_q.order())

    c = key.encrypt(m, r)
    c_i = [key.encrypt(m, r_alt)] + [
        key.encrypt(key.G_q.get_random_element()) for _ in range(n_alternatives - 1)
    ]

    durations_proof: List[int] = []
    durations_verify: List[int] = []
    for _ in tqdm(range(iterations)):
        start = time.time_ns()
        proof = proof_plaintext_equality_or(key, c, r, c_i, 0, r_alt)
        stop = time.time_ns()
        durations_proof.append(stop - start)

        start = time.time_ns()
        result = verify_plaintext_equality_or(proof, key, c, c_i)
        stop = time.time_ns()
        durations_verify.append(stop - start)

        assert result

    average_proof = sum(durations_proof) // len(durations_proof)
    average_verify = sum(durations_verify) // len(durations_verify)

    logger.info(
        f"Benchmarking complete - average duration: {average_proof} ns for proof, {average_verify} for verify"
    )
    benchmark_results["plaintext_equality_or_proof"] = average_proof
    benchmark_results["plaintext_equality_or_verify"] = average_verify


def benchmark_zkp_plaintext_dlog(args: Dict[str, any]) -> None:
    iterations = args["iterations"]

    key = ElGamalKeypair.generate(settings.p, settings.g)
    base = key.G_q.get_random_element()
    exp = random_integer(2, key.G_q.order())
    m = key.G_q.powmod(base, exp)
    r = random_integer(0, key.G_q.order())
    c = key.encrypt(m, r)

    durations_proof: List[int] = []
    durations_verify: List[int] = []
    for _ in tqdm(range(iterations)):
        start = time.time_ns()
        proof = proof_plaintext_dlog(key, c, base, exp, r)
        stop = time.time_ns()
        durations_proof.append(stop - start)

        start = time.time_ns()
        result = verify_plaintext_dlog(proof, key, c, base)
        stop = time.time_ns()
        durations_verify.append(stop - start)

        assert result

    average_proof = sum(durations_proof) // len(durations_proof)
    average_verify = sum(durations_verify) // len(durations_verify)

    logger.info(
        f"Benchmarking complete - average duration: {average_proof} ns for proof, {average_verify} for verify"
    )
    benchmark_results["plaintext_dlog_proof"] = average_proof
    benchmark_results["plaintext_dlog_verify"] = average_verify


def benchmark_elgamal_encrypt_decrypt(args: Dict[str, any]) -> None:
    iterations = args["iterations"]

    key = ElGamalKeypair.generate(settings.p, settings.g)
    m = key.G_q.get_random_element()

    durations_encrypt: List[int] = []
    durations_decrypt: List[int] = []
    for _ in tqdm(range(iterations)):
        r = random_integer(0, key.G_q.order())
        start = time.time_ns()
        c = key.encrypt(m, r)
        stop = time.time_ns()
        durations_encrypt.append(stop - start)

        start = time.time_ns()
        result = key.decrypt(c)
        stop = time.time_ns()
        durations_decrypt.append(stop - start)

        assert result == m

    average_encrypt = sum(durations_encrypt) // len(durations_encrypt)
    average_decrypt = sum(durations_decrypt) // len(durations_decrypt)

    logger.info(
        f"Benchmarking complete - average duration: {average_encrypt} ns for encryption,"
        f" {average_decrypt} for decryption"
    )
    benchmark_results["elgamal_encrypt"] = average_encrypt
    benchmark_results["elgamal_decrypt"] = average_decrypt


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="Benchmarking Tool",
        description="Benchmarks basic operations (powmod, sha256, ZKPs, ElGamal)",
        add_help=True,
    )

    ops = {
        "rng": benchmark_rng,
        "powmod": benchmark_powmod,
        "sha256": benchmark_sha256,
        "zkp_correct_decryption": benchmark_zkp_correct_decryption,
        "zkp_plaintext_equality_or": benchmark_zkp_plaintext_equality_or,
        "zkp_plaintext_dlog": benchmark_zkp_plaintext_dlog,
        "elgamal_encrypt_decrypt": benchmark_elgamal_encrypt_decrypt,
    }

    parser.add_argument(
        "--output",
        required=False,
        type=str,
        default="benchmark.json",
        help="Path to the output.",
    )
    parser.add_argument(
        "--op",
        required=True,
        type=str,
        choices=ops.keys(),
        help="Operation to benchmark",
    )
    parser.add_argument(
        "--iterations",
        required=False,
        type=int,
        default=1_000_000,
        help="Iterations for chosen OP",
    )
    parser.add_argument(
        "--n_alternatives",
        required=False,
        type=int,
        default=4,
        help="Alternative ciphertexts in the OR-proof",
    )
    args = parser.parse_args()

    logger.info(f"Benchmarking {args.op}- {args.iterations} iterations")
    ops[args.op](vars(args))

    with open(args.output, mode="w") as fp:
        json.dump({"iterations": args.iterations, "results": benchmark_results}, fp)


if __name__ == "__main__":
    main()

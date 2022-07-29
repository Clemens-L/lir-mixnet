import logging
import argparse
import itertools
import os
import subprocess
from shutil import copy, copytree
from typing import List
from collections.abc import Iterable
from datetime import datetime
from tqdm import tqdm

logger = logging.getLogger(__name__)
logging.basicConfig(
        level=logging.DEBUG,
        format=f"%(asctime)s %(module)s: %(message)s",
)

EVAL_TIMESTAMP = datetime.now().strftime("%Y-%m-%dT%H-%M-%S%z")


def evaluate_config(iter: int, num_mixpeers: int, num_consortiumpeers: int, num_inputs: int,
                    recovery_mode: int, precomputed_dkg: bool) -> None:
    path = os.path.join("output", EVAL_TIMESTAMP,
                        f"m{num_mixpeers}_c{num_consortiumpeers}_u{num_inputs}_r{recovery_mode}_{iter}")

    # copy ElGamal keypairs to evaluation directory
    os.makedirs(path)
    copy("keypairs.json", path)

    os.environ.update({
        "NUM_MIXPEERS": str(num_mixpeers),
        "NUM_CONSORTIUMPEERS": str(num_consortiumpeers),
        "NUM_INPUTS": str(num_inputs),
        "PEER_OUTPUT_DIRECTORY": path,
        "EVAL_TIMESTAMP": EVAL_TIMESTAMP,
    })
    if recovery_mode:
        os.environ.update({
            "SINGLE_RECOVERY": "",
        })
    else:
        if "SINGLE_RECOVERY" in os.environ:
            del os.environ["SINGLE_RECOVERY"]

    if precomputed_dkg:
        # copy the precomputed DKG folder to the path
        src = f"precomputed_dkg/{num_consortiumpeers}/consortium"
        dst = os.path.join(path, "consortium")
        copytree(src, dst)
        os.environ.update({
            "SKIP_CONSORTIUM_DKG": "",
        })
    else:
        if "SKIP_CONSORTIUM_DKG" in os.environ:
            del os.environ["SKIP_CONSORTIUM_DKG"]

    result = subprocess.run(
        ["./mixnet_execution.sh"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    with open(os.path.join(path, "shell.log"), mode="w") as fp:
        fp.write(result.stdout.decode("utf-8"))

    # remove the temporary copy of ElGamal keypairs from the evaluation directory
    os.remove(os.path.join(path, "keypairs.json"))


def create_param_list(code: str) -> List[int]:
    output = eval(code)
    # single int? put it in a list, return
    if isinstance(output, int):
        return [output]
    # iterable (like range())? cast it to list(), return
    if isinstance(output, Iterable):
        return list(output)
    # list? just return
    if isinstance(output, list):
        return output
    raise RuntimeError(f"Invalid parameter type: {type(output)} from code {code}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="Evaluation script for mixing network and identity recovery",
        usage="Specify the range of configurations to test",
        description="Evaluates performance of different mixing and recovery configurations.",
        add_help=True
    )
    # configuration parameters:
    # number of mixing peers: [1..n]
    # number of consortium peers: [1..n]
    # number of user inputs: [1..settings.max_n]
    parser.add_argument("--range_mix_peers", required=True, type=str,
                        help="Python expression for the list of all mixing peer configurations to test.")
    parser.add_argument("--range_consortium_peers", required=True, type=str,
                        help="Python expression for the list of all consortium peer configurations to test.")
    parser.add_argument("--range_user_inputs", required=True, type=str,
                        help="Python expression for the list of all numbers of user inputs to test.")
    parser.add_argument("--recovery", type=str, default="[0]",
                        help="Specify which modes to execute for the identity recovery (0: full, 1: single)")
    parser.add_argument("--iters", required=False, type=int, default=1,
                        help="Specify how many iterations to perform for each configuration.")
    parser.add_argument("--precomputed-dkg", action="store_true",
                        help="Use precomputed DKG values for the consortium.")
    args = parser.parse_args()

    # create lists of ints from the given python expressions
    mix_peer_params = create_param_list(args.range_mix_peers)
    consortium_peers_params = create_param_list(args.range_consortium_peers)
    user_inputs_params = create_param_list(args.range_user_inputs)
    recovery_modes = create_param_list(args.recovery)
    iterations = list(range(args.iters))
    precomputed_dkg = [args.precomputed_dkg]

    # compute cross product of all parameter ranges to obtain all configurations to evaluate
    configs = list(
        itertools.product(
            iterations,
            mix_peer_params,
            consortium_peers_params,
            user_inputs_params,
            recovery_modes,
            precomputed_dkg,
        )
    )
    logger.info(f"Evaluating {len(configs)} different configurations.")

    for cfg in tqdm(configs):
        evaluate_config(*cfg)


if __name__ == '__main__':
    main()

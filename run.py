import argparse
import json
import os
import sys
import re
import logging
import signal
import subprocess
from typing import Dict, List
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from settings import HTTP_BASE_PORT

logger = logging.getLogger(__name__)


# http retry strategy for checking if peers are ready
retry_strategy = Retry(
    total=6,
    backoff_factor=1
)
adapter = HTTPAdapter(max_retries=retry_strategy)
http = requests.Session()
http.mount("http://", adapter)


def get_running_pids() -> List[int]:
    try:
        with open("pidfile.txt", mode="r") as fp:
            pidfile = json.load(fp)
            pids = pidfile["pids"]
            assert len(pids) == pidfile["numpeers"]
            return pids
    except (FileNotFoundError, json.JSONDecodeError, KeyError, AssertionError) as e:
        return []


def start(args: Dict) -> None:
    if get_running_pids():
        raise RuntimeError("Network already running!")

    numpeers = args.get("numpeers")
    pidfile = {"numpeers": args.get("numpeers"), "pids": []}
    logprefix = args.get("logprefix")
    mdkg = args.get("maliciousdkg")
    mthres = args.get("maliciousthres")
    sr = args.get("singlerecovery")

    for i in range(numpeers):
        cli_args = ["python", "peer.py", "--numpeers", f"{numpeers}", "--id", f"{i}", "--logprefix", f"{logprefix}"]
        if i >= (numpeers - mdkg):
            cli_args.append("--maliciousdkg")
        if i >= (numpeers - mthres):
            cli_args.append("--maliciousthres")
        if sr:
            cli_args.append("--singlerecovery")
        p = subprocess.Popen(cli_args)
        pidfile["pids"].append(p.pid)

    with open("pidfile.txt", mode="w") as fp:
        json.dump(pidfile, fp)

    # at this point, wait for all peers to be responsive
    for i in range(numpeers):
        try:
            # wait for peer to be ready
            http.get(f"http://127.0.0.1:{HTTP_BASE_PORT+i}/")
            logger.info(f"Peer {i} is ready.")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Peer {i} was not ready in time. Restarting peers ...")
            stop(args)
            start(args)


def stop(args: Dict) -> None:
    kill = args.get("kill")

    pids = get_running_pids()
    if not pids:
        raise RuntimeError("Network is not running!")

    for pid in pids:
        try:
            if kill:
                logger.warning(f"Sending SIGKILL to {pid} ...")
                os.kill(pid, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGTERM)
        except ProcessLookupError as e:
            print(f"{e} (pid = {pid})")

    os.remove("pidfile.txt")


def clean(args: Dict) -> None:
    logprefix = args.get("logprefix")
    regex = re.compile(f"{logprefix}[0-9]+.log")
    for fname in os.listdir("."):
        if regex.match(fname):
            logger.debug(f"Deleting logfile {fname}")
            os.remove(fname)


def start_clean(args: Dict) -> None:
    clean(args)
    start(args)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="Startup script for network of peers",
        usage="Specify size and configuration of network, as well as the desired action.",
        description="Starts and stops the peers of the network",
        add_help=True
    )
    parser.add_argument("action", nargs='?', type=str, default="start",
                        choices=["start", "stop", "clean", "start-clean"])
    parser.add_argument("--numpeers", required=False, type=int, default=4,
                        help="Number of total peers in this network.")
    parser.add_argument("--logprefix", type=str, default="peer",
                        help="Prefix for the logfiles ([prefix][id].log)")
    parser.add_argument("-mdkg", "--maliciousdkg", type=int, help="Number of malicious peers during DKG.", default=0)
    parser.add_argument("-mthres", "--maliciousthres", type=int, help="Number of malicious peers during "
                                                                      "threshold encryption", default=0)
    parser.add_argument("-sr", "--singlerecovery", action="store_true", help="Enable the recovery of single identities")
    parser.add_argument("-k", "--kill", action="store_true", help="Makes the stop command send SIGKILL")

    args = parser.parse_args()

    eval_timestamp = os.environ.get("EVAL_TIMESTAMP")
    log_path = os.path.join("output", eval_timestamp) if eval_timestamp else "."
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s %(module)s: %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(log_path, "run.log")),
            logging.StreamHandler(sys.stdout)
        ]
    )

    func = {
        "start": start,
        "stop": stop,
        "clean": clean,
        "start-clean": start_clean,
    }
    func[args.action](dict(args.__dict__))


if __name__ == '__main__':
    main()

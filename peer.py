import argparse
import asyncio
import os
import sys
import socket

import logging
import json
from aiohttp import web
from pathlib import Path

import measurement
import settings
import protocols
from integer import IntJSONDecoder

import mixnet_web
import consortium_web

routes = web.RouteTableDef()

logger = logging.getLogger(__name__)


@routes.get("/")
async def default_handler(_: web.Request):
    # used by the run.py script to determine whether this peer process is responsive yet or still booting up
    return web.Response(
        text="READY",
        content_type="text/html"
    )


@routes.post("/peer")
async def peer_handler(request: web.Request):
    text = await request.text()
    msg = json.loads(text, cls=IntJSONDecoder)
    logger.debug(f"Received msg: {msg}")
    # process the protocol concurrently so that we can send the response immediately
    # (otherwise, the remote peer may be blocking)
    asyncio.get_running_loop().create_task(protocols.ProtocolState.init_from_msg(msg).process(msg))
    return web.Response(text="")


app = web.Application(client_max_size=(1024**3))
app.add_routes(routes)
app.add_routes(mixnet_web.routes)
app.add_routes(consortium_web.routes)


async def on_startup(_):
    measurement.begin_measurement()


async def on_shutdown(_):
    measurement.end_measurement(f"{settings.LOGPREFIX}-timings{settings.PEER_ID}.json")


app.on_startup.append(on_startup)
app.on_shutdown.append(on_shutdown)


def main():
    parser = argparse.ArgumentParser(
        prog="Deanonymization Peer",
        usage="Assign this peer an (unique) identifier to let it participate in the network",
        description="Participates in cryptographic protocols ...",
        add_help=True
    )
    parser.add_argument("--numpeers", required=True, type=int, help="Number of total peers in this network.")
    parser.add_argument("--id", required=True, type=int, help="Unique numeric identifier of this peer in the network")
    parser.add_argument("--logprefix", type=str, default="peer", help="Prefix for the logfiles ([prefix][id].log)")
    parser.add_argument("-mdkg", "--maliciousdkg", action="store_true", help="Makes this peer malicious during DKG")
    parser.add_argument("-mthres", "--maliciousthres", action="store_true", help="Makes this peer malicious during "
                                                                                 "threshold encryption")
    parser.add_argument("-sr", "--singlerecovery", action="store_true", help="Enable the recovery of single identities")
    args = parser.parse_args()

    settings.NUM_PEERS = args.numpeers
    settings.PEER_ID = args.id
    settings.HTTP_PORT = settings.HTTP_BASE_PORT + settings.PEER_ID
    settings.LOGPREFIX = args.logprefix
    settings.MALICIOUS_DKG = args.maliciousdkg
    settings.MALICIOUS_THRES_DECR = args.maliciousthres
    settings.SINGLE_RECOVERY = args.singlerecovery

    # if environment variable is set, chdir accordingly to redirect output
    peer_output_directory = os.environ.get("PEER_OUTPUT_DIRECTORY")
    if peer_output_directory:
        # create output directory, if necessary
        Path(peer_output_directory).mkdir(parents=True, exist_ok=True)
        os.chdir(peer_output_directory)

    logging.basicConfig(
        level=logging.INFO,
        format=f"[PEER {settings.PEER_ID}] - %(asctime)s %(module)s: %(message)s",
        handlers=[
            logging.FileHandler(f"{settings.LOGPREFIX}{settings.PEER_ID}.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

    settings.load_config()

    logger.info(f"Starting peer {settings.PEER_ID}, listening on port {settings.HTTP_PORT}")

    if settings.MALICIOUS_DKG:
        logger.info("This peer will act maliciously during distributed key generation.")

    if settings.MALICIOUS_THRES_DECR:
        logger.info("This peer will act maliciously during threshold decryption")

    if settings.SINGLE_RECOVERY:
        logger.info("Launching in SINGLE_RECOVERY mode.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", settings.HTTP_PORT))
    web.run_app(
        app,
        sock=sock,
        access_log=None,
        print=lambda _: None,
        shutdown_timeout=1,
    )


if __name__ == "__main__":
    main()

import logging
import json
from aiohttp import web
from gmpy2 import mpz

import mixnet
import protocols

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()


def get_mixnet_state() -> mixnet.MixnetState:
    """
    Returns the current mixnet state if it exists, or a fresh state otherwise.
    :return: A MixnetState object.
    """
    mn_states = [v for v in protocols.transaction_manager.values() if isinstance(v, mixnet.MixnetState)]
    if len(mn_states) == 0:
        return mixnet.MixnetState.init_new()
    # currently we can only have one MixnetState instance at any given time
    assert len(mn_states) == 1
    return mn_states[0]


@routes.get("/mix/info")
async def mixnet_info_handler(request: web.Request):
    return web.json_response(get_mixnet_state().info())


@routes.post("/mix/keygen")
async def mixnet_keygen_handler(request: web.Request):
    await get_mixnet_state().perform_keygen()
    raise web.HTTPOk


@routes.post("/mix/register")
async def mixnet_register_handler(request: web.Request):
    data = await request.json()
    a = mpz(data["a"])
    b = mpz(data["b"])

    logger.debug(f"Received user input ({a}, {b})")

    await get_mixnet_state().perform_register(a, b)

    raise web.HTTPOk


@routes.post("/mix/commit")
async def mixnet_commit_handler(request: web.Request):
    await get_mixnet_state().perform_commit()
    raise web.HTTPOk


@routes.post("/mix/perform")
async def mixnet_perform_handler(request: web.Request):
    await get_mixnet_state().perform()
    raise web.HTTPOk


@routes.post("/mix/decrypt")
async def mixnet_decrypt_handler(request: web.Request):
    await get_mixnet_state().perform_decrypt()
    raise web.HTTPOk

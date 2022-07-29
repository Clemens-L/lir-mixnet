import logging
import math
from aiohttp import web

import settings
import dkg
from integer import SchnorrGroup
from consortium import ConsortiumStateFullRecovery, ConsortiumStateSingleRecovery

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()


@routes.post("/consortium/keygen")
async def dkg_handler(request: web.Request):
    # performs DKG for the consortium, saves the secret information and the public key to disk
    state = dkg.DistributedKeyGeneration.init_new()
    G_q = SchnorrGroup(settings.p)
    g, h = settings.g, settings.h
    state.set_params(G_q, g, h, math.ceil(settings.NUM_PEERS / 2))
    await state.perform()

    await state.save_all([f"consortium/dkg.{i}.json" for i in range(settings.NUM_PEERS)])
    state.public_key.save("consortium/pk.json")

    return web.Response(text=f"Public Key = {state.y}")


@routes.post("/consortium/recover")
async def consortium_recover_handler(request: web.Request):
    if not settings.SINGLE_RECOVERY:
        state_full_recovery = ConsortiumStateFullRecovery.init_new()
        await state_full_recovery.perform()
    else:
        state_single_recovery = ConsortiumStateSingleRecovery.init_new()
        # with single identity recovery, we have to specify which output to deanonymize
        state_single_recovery.set_output_index(0)
        await state_single_recovery.perform()

    return web.Response()

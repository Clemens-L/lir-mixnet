import random
import json
from typing import List, Dict

import gmpy2
from gmpy2 import mpz

import integer
import elgamal


# a "double" safe prime p, such that q = (p-1)/2 is also a safe prime.
# (see also: "cunningham chain")
# bit-length 2050
p = mpz(
    "1033545645415797360778763280836182580964035987608373578902992609"
    "6589616689346278877500797391852875986096100569254563896599580022"
    "9856006561595230483636794519244711320805563726743097098326378439"
    "2374049589914972274932939951764052890984183529118179949140839565"
    "1942820239737493822043299258861569861501412319860707159615257023"
    "3567763093493312239701946933512069003275737374370764129080886324"
    "7368754309161230885395793305496508554444670616229953388703660473"
    "6203954852914861665228668787831614761775442286097630005503447558"
    "1202324323375074130076535632204287980008583033130140442109824466"
    "542124214481979040881537893484608188705647"
)
# bit-length 2049
q = (p-1)//2
# bit-length 2048
r = (q-1)//2
assert gmpy2.is_prime(p)
assert p.bit_length() == 2050
assert gmpy2.is_prime(q)
assert q.bit_length() == 2049
assert gmpy2.is_prime(r)
assert r.bit_length() == 2048
# g and h are public generators of Z_p^* of order q
g = mpz(
    "5507479360905905880284834206731552163686955480522378180625119078"
    "5522579080748929224061540354115425303537286237294676132003709094"
    "4288547896240210155924098293997381558780788149297491401648390602"
    "2931632892201827429533368045497206256718277296717491957221974801"
    "6936161404909404285247889558686135137782933396348295421526773652"
    "3106759777718567482307625469770837848986712096394719599249787263"
    "2461645629825957012973068930683303488050095568650433794528811978"
    "4644413132911099681719612052984672053573594158683477648297522976"
    "4454233512011113766973021703758466381841931508117374948213000501"
    "53445589100585150703928806508847147349330"
)
h = mpz(
    "9814996163727242432812263795415767931670674050647900743956219533"
    "0716151252773007356776933569084859357497720565893793905232652802"
    "6904075118357925568809961001283885094151406078763363938510340736"
    "7159388584119220098654597666085566799257569189617647663902212515"
    "3924041586143314097190574499722350695746580247076365586338041010"
    "1095947878574252425521575825804099614763865498409353228556130179"
    "9611371028649627575813872295971711691894079705807585184860880611"
    "4114870131891616493221076267078275863400184952240306922385519866"
    "8634420771943212880818405217234807070265140021943566308373566288"
    "54945923341604585534304914526127795570658"
)
# max_n public generators of Z_p^* of order q
max_n = 1000
_rng_backup = integer.rng
# make randomness deterministic so that we always use the same generators
integer.rng = random.Random(x=0)
G_q = integer.SchnorrGroup(p)
h_i = [G_q.get_random_generator() for _ in range(max_n)]
# restore PRNG
integer.rng = _rng_backup

HTTP_BASE_PORT = 32768
NUM_PEERS = -1
PEER_ID = -1
HTTP_PORT = -1
LOGPREFIX = None

MALICIOUS_DKG = False
MALICIOUS_THRES_DECR = False

SINGLE_RECOVERY = False

ELGAMAL_KEYS: Dict[int, elgamal.ElGamalKeypair] = {}


def load_config() -> None:
    """
    Loads elgamal keypair for this peer from a config file.
    Call this once after parsing commandline arguments in peer.py
    """
    global ELGAMAL_KEYS
    with open("keypairs.json", mode="r") as fp:
        keypairs = json.load(fp, cls=integer.IntJSONDecoder)

    for i in range(NUM_PEERS):
        pair = keypairs[str(i)]
        # if it is our keypair, instantiate with private key
        if i == PEER_ID:
            ELGAMAL_KEYS[i] = elgamal.ElGamalKeypair.construct(p, g, pair["y"], pair["x"])
        else:
            ELGAMAL_KEYS[i] = elgamal.ElGamalKeypair.construct(p, g, pair["y"], None)


def peer_port(pid: int) -> int:
    """
    Returns the port on which the peer with id 'pid' is listening for HTTP requests
    :param pid: ID of the corresponding oeer
    :return: HTTP port of that peer
    """
    return HTTP_BASE_PORT + pid


def all_peer_ports() -> List[int]:
    """
    Returns a list containing all peer ports, excluding this peer
    :return: A list of HTTP ports.
    """
    return [peer_port(pid) for pid in range(NUM_PEERS) if pid != PEER_ID]


def all_peer_ids() -> List[int]:
    """
    Returns a list containing all peer ids, excluding this peer
    :return: A list of all peer ids, excluding the local one.
    """
    return [pid for pid in range(NUM_PEERS) if pid != PEER_ID]

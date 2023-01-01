import web3
from eth_keys import keys, datatypes
from eth_account._utils.typed_transactions import TypedTransaction
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from tqdm import tqdm


def recover_public_key(tx_raw):
    tx = TypedTransaction.from_bytes(tx_raw)
    sig = datatypes.Signature(vrs=tx.vrs())
    return keys.ecdsa_recover(tx.hash(), sig)


def hash_point(P):
    return (P.x, P.y)


def MITM_naive(lhs, rhs, M):
    tbl = {}
    for low in tqdm(range(M)):
        tbl[hash_point(lhs - low * rhs)] = low

    rhsM = rhs * M
    for high in tqdm(range(M)):
        if hash_point(high * rhsM) in tbl:
            return tbl[hash_point(high * rhsM)] + high * M


def MITM_optimized(lhs, rhs, M):
    tbl = {}
    tmp = lhs
    for low in tqdm(range(M)):
        tbl[(tmp.x, tmp.y)] = low
        tmp -= rhs

    rhsM = rhs * M
    tmp = rhsM * 0
    for high in tqdm(range(M)):
        if (tmp.x, tmp.y) in tbl:
            return tbl[(tmp.x, tmp.y)] + high * M
        tmp += rhsM


sepolia = web3.providers.HTTPProvider("https://rpc.sepolia.org/")
w3 = web3.Web3(sepolia)
tx_raw = w3.eth.get_raw_transaction(
    "0x39f9e9279472d9ab7986fe380fae9693e91003104bb892c953e73b6a2f878ac2"
)
print(tx_raw)
pub = recover_public_key(tx_raw)
print(pub)
assert pub.to_checksum_address() == "0x891cf17281bF2a57b25620b144A4E71B395603D4"

pb = pub.to_bytes()
x = int.from_bytes(pb[:32], "big")
y = int.from_bytes(pb[32:], "big")
P = Point(x, y, curve=secp256k1)
print(P)

# P = x * G = (c + s * r) * G
# c = ictf{??????}
# s = 256
# r = ??????
# P - c * G = r * (s * G)
# lhs = P - c * G
# rhs = s * G
c = int.from_bytes(b"ictf{\x00\x00\x00\x00\x00\x00}".rjust(32, b"\x00"), "big")
lhs = P - c * secp256k1.G
rhs = 256 * secp256k1.G
# r = MITM_naive(lhs, rhs, 1 << 24)
r = MITM_optimized(lhs, rhs, 1 << 24)
print(r)
print(r.to_bytes(6, "big"))

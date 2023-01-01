import web3
from eth_keys import keys, datatypes
from eth_account._utils.typed_transactions import DynamicFeeTransaction
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from tqdm import tqdm


def recover_public_key(tx):
    # https://ethereum.stackexchange.com/questions/13778/get-public-key-of-any-ethereum-account doesn't work now
    # it seems there are multiple types of Ethereum transactions
    # and the one used in this challenge is type 2, which is DynamicFeeTransaction
    # https://github.com/ethereum/eth-account/blob/a8d6436200feaf161bc7f040ec6360a91f0b40c1/eth_account/_utils/typed_transactions.py#L403
    # print(tx)
    sig = datatypes.Signature(
        vrs=(tx.v, int(bytes(tx.r).hex(), 16), int(bytes(tx.s).hex(), 16))
    )
    dt = DynamicFeeTransaction.from_dict(
        {
            k: tx[k]
            for k in {
                "type",
                "nonce",
                "chainId",
                "maxPriorityFeePerGas",
                "maxFeePerGas",
                "gas",
                "to",
                "value",
                "accessList",
            }
        }
    )
    return keys.ecdsa_recover(dt.hash(), sig)


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


sepolia = web3.providers.HTTPProvider(
    # official https://rpc.sepolia.dev/ have outdated SSL certificate...
    "https://web3-trial.cloudflare-eth.com/v1/sepolia"
)
w3 = web3.Web3(sepolia)
tx = w3.eth.get_transaction(
    "0x39f9e9279472d9ab7986fe380fae9693e91003104bb892c953e73b6a2f878ac2"
)
print(tx)
"""
AttributeDict({'blockHash': HexBytes('0xb1abf986ee1dbd960f5b8928447de495ebbef6235601c1e25f6aa9b3636946d1'), 'blockNumber': 2415790, 'from': '0x891cf17281bF2a57b25620b144A4E71B395603D4', 'gas': 21000, 'gasPrice': 2425000007, 'maxFeePerGas': 2425000008, 'maxPriorityFeePerGas': 2425000000, 'hash': HexBytes('0x39f9e9279472d9ab7986fe380fae9693e91003104bb892c953e73b6a2f878ac2'), 'input': '0x', 'nonce': 0, 'to': '0xB2A8E24a90E5B5F7f4CBD26D350B83674652D65e', 'transactionIndex': 6, 'value': 100000000000000, 'type': '0x2', 'accessList': [], 'chainId': '0xaa36a7', 'v': 1, 'r': HexBytes('0x97136af95847ac005436016f0dca6b01f4132d16b38edd4aea3458c339dca938'), 's': HexBytes('0x5319320f10bfcaafa49f55134fcb216e62d1c9e16fd4364dbf8913332278322e')})
"""

pub = recover_public_key(tx)
print(pub)

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

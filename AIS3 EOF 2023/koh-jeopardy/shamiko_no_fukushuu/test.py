import hmac
from hashlib import sha256

secret = b'xxx'
# key1 = b'a' * 65
# key2 = sha256(key1).digest()
key1 = b'asd'
key2 = key1 + b'\x00'
print(hmac.digest(key1, secret, sha256).hex())
print(hmac.digest(key2, secret, sha256).hex())

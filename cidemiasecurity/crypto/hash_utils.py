import base64
from hashlib import sha1


def hash_token(token: str) -> str:
    result = sha1()
    result.update(token.encode('utf-8'))
    result = result.digest()
    result = encode_base64(result)
    return result


def decode_base64(source):
    return base64.b64decode(source).decode('utf-8')


def encode_base64(source: bytes):
    return base64.b64encode(source).decode("utf-8")

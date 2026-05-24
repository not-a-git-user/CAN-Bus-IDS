import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict

_PBKDF2_ITERS = 200_000
_KEY_LEN = 32
_NONCE_LEN = 16
_SALT_LEN = 16


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(val: str) -> bytes:
    return base64.b64decode(val.encode("ascii"))


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERS,
        dklen=_KEY_LEN,
    )


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        counter_bytes = counter.to_bytes(4, "big")
        block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_data(data: Any, password: str) -> bytes:
    plaintext = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key = _derive_key(password, salt)
    stream = _keystream(key, nonce, len(plaintext))
    ciphertext = _xor_bytes(plaintext, stream)
    tag = hmac.new(key, b"v1" + nonce + ciphertext, hashlib.sha256).digest()
    envelope = {
        "version": 1,
        "cipher": "xor-hkdf-sha256",
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
        "tag": _b64e(tag),
    }
    payload = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if not payload.strip():
        raise ValueError("Encrypted payload is empty")
    return payload


def is_encrypted_envelope(obj: Dict[str, Any]) -> bool:
    return all(k in obj for k in ("ciphertext", "nonce", "salt", "tag", "version"))


def decrypt_data(encrypted: bytes, password: str) -> Any:
    envelope = json.loads(encrypted.decode("utf-8"))
    if not is_encrypted_envelope(envelope):
        raise ValueError("Not an encrypted envelope")
    if envelope.get("version") != 1:
        raise ValueError("Unsupported envelope version")
    salt = _b64d(envelope["salt"])
    nonce = _b64d(envelope["nonce"])
    ciphertext = _b64d(envelope["ciphertext"])
    tag = _b64d(envelope["tag"])
    key = _derive_key(password, salt)
    expected = hmac.new(key, b"v1" + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Integrity check failed")
    stream = _keystream(key, nonce, len(ciphertext))
    plaintext = _xor_bytes(ciphertext, stream)
    return json.loads(plaintext.decode("utf-8"))

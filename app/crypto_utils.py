import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_key_pair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(private_der), b64e(public_raw)


def sign_b64(private_key_b64: str, message: bytes) -> str:
    private_key = serialization.load_der_private_key(b64d(private_key_b64), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Stored signing key is not an Ed25519 key")
    return b64e(private_key.sign(message))


def verify_b64(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64d(public_key_b64))
        public_key.verify(b64d(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError, base64.binascii.Error):
        return False

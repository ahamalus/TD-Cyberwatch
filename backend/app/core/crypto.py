"""Authenticated encryption for stored hosting credentials.

AES-256-GCM with a keyring loaded from configuration (``CW_CREDENTIAL_KEYS``).
Keys live outside the database. Each ciphertext records the key id used, so
keys can be rotated: add a new key at the front of the list, run the
re-encryption command, then retire the old key.

The associated data binds a ciphertext to its tenant and owning record, so a
ciphertext copied to another tenant's row fails to decrypt.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialVaultError(Exception):
    pass


@dataclass(frozen=True)
class EncryptedBlob:
    key_id: str
    nonce: bytes
    ciphertext: bytes


class CredentialVault:
    def __init__(self, keyring_spec: str):
        self._keys: dict[str, bytes] = {}
        self._primary: str | None = None
        for entry in [e.strip() for e in keyring_spec.split(",") if e.strip()]:
            if ":" not in entry:
                raise CredentialVaultError("Credential key entries must be 'key_id:base64key'.")
            key_id, b64 = entry.split(":", 1)
            try:
                key = base64.b64decode(b64, validate=True)
            except Exception as exc:  # noqa: BLE001
                raise CredentialVaultError(f"Credential key '{key_id}' is not valid base64.") from exc
            if len(key) != 32:
                raise CredentialVaultError(f"Credential key '{key_id}' must be 32 bytes.")
            self._keys[key_id] = key
            if self._primary is None:
                self._primary = key_id

    @property
    def configured(self) -> bool:
        return self._primary is not None

    @property
    def primary_key_id(self) -> str:
        if self._primary is None:
            raise CredentialVaultError("No credential encryption key is configured.")
        return self._primary

    @staticmethod
    def associated_data(tenant_id: object, record_id: object, purpose: str) -> bytes:
        return f"cyberwatch:{purpose}:{tenant_id}:{record_id}".encode()

    def encrypt(self, plaintext: bytes, aad: bytes) -> EncryptedBlob:
        key_id = self.primary_key_id
        nonce = os.urandom(12)
        ct = AESGCM(self._keys[key_id]).encrypt(nonce, plaintext, aad)
        return EncryptedBlob(key_id=key_id, nonce=nonce, ciphertext=ct)

    def decrypt(self, blob: EncryptedBlob, aad: bytes) -> bytes:
        key = self._keys.get(blob.key_id)
        if key is None:
            raise CredentialVaultError(f"Credential key '{blob.key_id}' is not available.")
        try:
            return AESGCM(key).decrypt(blob.nonce, blob.ciphertext, aad)
        except InvalidTag as exc:
            raise CredentialVaultError("Credential integrity check failed.") from exc

    def needs_rotation(self, blob: EncryptedBlob) -> bool:
        return blob.key_id != self.primary_key_id


def generate_key_entry(key_id: str = "k1") -> str:
    return f"{key_id}:{base64.b64encode(os.urandom(32)).decode()}"


def fingerprint(data: bytes) -> str:
    """Non-reversible short fingerprint suitable for display (never the secret itself)."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")[:16]


_vault: CredentialVault | None = None


def get_vault() -> CredentialVault:
    global _vault
    if _vault is None:
        from app.core.config import get_settings

        _vault = CredentialVault(get_settings().credential_keys.get_secret_value())
    return _vault


def reset_vault() -> None:
    global _vault
    _vault = None

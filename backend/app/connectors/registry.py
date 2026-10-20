"""Connector registry: maps connector keys to adapter implementations."""

from __future__ import annotations

import json

from app.connectors.base import ConnectionParams, Connector, ConnectorError, SecretMaterial
from app.connectors.cpanel import CPanelUAPIConnector
from app.connectors.sftp import SFTPConnector
from app.core.crypto import CredentialVault, EncryptedBlob, get_vault
from app.models import ConnectorDefinition, HostingAccount, HostingCredential

ADAPTERS: dict[str, type[Connector]] = {
    SFTPConnector.key: SFTPConnector,
    CPanelUAPIConnector.key: CPanelUAPIConnector,
}

# Credential kinds each connector accepts.
ACCEPTED_SECRET_KINDS = {
    "sftp": ("password", "private_key"),
    "cpanel_uapi": ("api_token",),
}

DEFAULT_PORTS = {"sftp": 22, "cpanel_uapi": 2083}


def is_implemented(key: str) -> bool:
    return key in ADAPTERS


def credential_aad(cred: HostingCredential) -> bytes:
    return CredentialVault.associated_data(cred.tenant_id, cred.hosting_account_id, "hosting_credential")


def encrypt_secret(tenant_id, account_id, secret: SecretMaterial) -> tuple[str, bytes, bytes]:
    payload = json.dumps({"kind": secret.kind, "value": secret.value, "passphrase": secret.passphrase}).encode()
    blob = get_vault().encrypt(
        payload, CredentialVault.associated_data(tenant_id, account_id, "hosting_credential")
    )
    return blob.key_id, blob.nonce, blob.ciphertext


def decrypt_secret(cred: HostingCredential) -> SecretMaterial:
    raw = get_vault().decrypt(EncryptedBlob(cred.key_id, cred.nonce, cred.ciphertext), credential_aad(cred))
    data = json.loads(raw)
    return SecretMaterial(kind=data["kind"], value=data["value"], passphrase=data.get("passphrase"))


def build_connector(
    account: HostingAccount,
    credential: HostingCredential | None,
    definition: ConnectorDefinition | None = None,
) -> Connector:
    cls = ADAPTERS.get(account.connector_type)
    if cls is None:
        raise ConnectorError("unsupported", f"Connector '{account.connector_type}' is not implemented yet.")
    if definition is not None and definition.status != "implemented":
        raise ConnectorError("unsupported", f"Connector '{account.connector_type}' is disabled by the platform.")
    params = ConnectionParams(
        connector_type=account.connector_type,
        hostname=account.hostname,
        port=account.port,
        username=account.username,
        root_path=account.root_path,
        options=dict(account.options or {}),
        expected_host_key=account.host_key_fingerprint,
        connect_timeout=definition.connect_timeout_seconds if definition else 15.0,
        io_timeout=definition.io_timeout_seconds if definition else 60.0,
    )
    secret = decrypt_secret(credential) if credential is not None else None
    return cls(params, secret)

"""WHM API connector (read-only): monitor one cPanel account through a reseller's or the server's WHM.

One WHM API token can reach every account the reseller owns, so a host or reseller connects once and adds
each customer account as its own connection (same hostname and WHM user, different ``cpanel_user``).

Calls go to ``https://<host>:2087/json-api/<function>?api.version=1`` with ``Authorization: whm
<user>:<token>``. Only these functions are ever called (enforced by ``ALLOWED_WHM`` and ``ALLOWED_UAPI``):

* ``accountsummary``: confirm the account exists, is owned by this WHM user, and whether it is suspended.
* ``uapi_cpanel`` with ``Fileman::list_files`` and ``Fileman::get_file_content``: the same read-only
  functions the cPanel connector uses, run as the chosen cPanel account. Its response wraps the normal
  UAPI result in ``data.uapi``.

VERIFICATION STATUS: built against WHM API 1 documentation and a simulated server; not yet verified on a
live WHM. Capability discovery reports only what it actually observes.

The token should be a **reseller** token restricted (in WHM → Manage API Tokens) to the ACLs these calls
need (*list-accts* and the account-functions privilege that allows ``uapi_cpanel``); a root token works but
is far more powerful than CyberWatch needs.
"""

from __future__ import annotations

import re
from typing import Any

from app.connectors.base import (
    AVAILABLE,
    E_AUTH,
    E_CONFIG,
    E_NOT_FOUND,
    E_PERMISSION,
    E_PROTOCOL,
    UNSUPPORTED,
    UNTESTED,
    Capability,
    CapabilityResult,
    ConnectionTestResult,
    ConnectorError,
    Diagnostic,
)
from app.connectors.cpanel import CPanelClient, CPanelFileSource, CPanelUAPIConnector

ALLOWED_WHM = frozenset({"accountsummary", "uapi_cpanel"})
ALLOWED_UAPI = frozenset({("Fileman", "list_files"), ("Fileman", "get_file_content")})
CPANEL_USER = re.compile(r"^[a-z][a-z0-9]{0,31}$")  # cPanel usernames: lowercase letters and digits


def valid_cpanel_user(name: str) -> bool:
    return bool(CPANEL_USER.match(name or ""))


class WHMClient(CPanelClient):
    label = "WHM"
    ports_setting = "allowed_whm_ports"

    def __init__(self, params, token: str, cpanel_user: str, keep_alive: bool = False):
        super().__init__(params, token, keep_alive=keep_alive)
        if not valid_cpanel_user(cpanel_user):
            raise ConnectorError(E_CONFIG, "A valid cPanel account name to monitor is required.")
        self.cpanel_user = cpanel_user

    def _auth_header(self) -> str:
        return f"whm {self.params.username}:{self._token}"

    def _endpoint(self, module: str, function: str, query: dict[str, str]) -> tuple[str, dict[str, str]]:
        if (module, function) not in ALLOWED_UAPI:
            raise ConnectorError(E_PROTOCOL, f"{module}::{function} is not on the read-only allow-list.")
        return "/json-api/uapi_cpanel", {"api.version": "1", "cpanel.user": self.cpanel_user,
                                         "cpanel.module": module, "cpanel.function": function, **query}

    def _unwrap(self, payload: Any) -> Any:
        self._check_metadata(payload)
        data = payload.get("data") if isinstance(payload, dict) else None
        return data.get("uapi") if isinstance(data, dict) else None

    def _check_metadata(self, payload: Any) -> None:
        meta = payload.get("metadata") if isinstance(payload, dict) else None
        if not isinstance(meta, dict):
            raise ConnectorError(E_PROTOCOL, "WHM returned a response without metadata.")
        if meta.get("result") in (0, "0", False):
            reason = str(meta.get("reason") or "unknown")[:300]
            lowered = reason.lower()
            if "access denied" in lowered or "permission" in lowered or "not authorized" in lowered \
                    or "do not have" in lowered or "not have access" in lowered:
                raise ConnectorError(E_PERMISSION, f"WHM denied the request: {reason}")
            if "does not exist" in lowered or "no such user" in lowered or "not found" in lowered \
                    or "does not own" in lowered:
                raise ConnectorError(E_NOT_FOUND, f"WHM: {reason}")
            raise ConnectorError(E_PROTOCOL, f"WHM reported an error: {reason}")

    def whm_call(self, function: str, query: dict[str, str]) -> Any:
        if function not in ALLOWED_WHM or function == "uapi_cpanel":
            raise ConnectorError(E_PROTOCOL, f"WHM function {function} is not on the read-only allow-list.")
        payload = self._get_json(f"/json-api/{function}", {"api.version": "1", **query})
        self._check_metadata(payload)
        return payload.get("data")

    def account_summary(self) -> dict[str, Any]:
        data = self.whm_call("accountsummary", {"user": self.cpanel_user})
        accts = data.get("acct") if isinstance(data, dict) else None
        if not accts or not isinstance(accts[0], dict):
            raise ConnectorError(E_NOT_FOUND, f"WHM has no account named {self.cpanel_user}.")
        return accts[0]


class WHMConnector(CPanelUAPIConnector):
    key = "whm_api"
    version = "0.9.0"

    @property
    def cpanel_user(self) -> str:
        return str(self.params.options.get("cpanel_user") or "")

    def _client(self, keep_alive: bool = False) -> WHMClient:
        if self.secret is None or self.secret.kind != "api_token":
            raise ConnectorError(E_CONFIG, "WHM requires a WHM API token.")
        return WHMClient(self.params, self.secret.value, self.cpanel_user, keep_alive=keep_alive)

    def test_connection(self) -> ConnectionTestResult:
        diags: list[Diagnostic] = []
        try:
            client = self._client()
            acct = client.account_summary()
            diags.append(Diagnostic("authentication", True, "WHM API token accepted."))
            suspended = str(acct.get("suspended", "0")) not in ("0", "", "False", "false")
            diags.append(Diagnostic(
                "account", True,
                f"cPanel account {self.cpanel_user} ({acct.get('domain') or 'no primary domain'})"
                + (" is SUSPENDED" if suspended else "") + f", owned by {acct.get('owner') or 'unknown'}."))
            source = CPanelFileSource(self.params.root_path, client)
            source.list_dir(".")
            diags.append(Diagnostic("root_listing", True, f"Listed authorised root {source.root} as {self.cpanel_user}."))
            return ConnectionTestResult(True, diags, server_info={"cpanel_user": self.cpanel_user,
                                                                  "domain": acct.get("domain"),
                                                                  "suspended": suspended})
        except ConnectorError as exc:
            step = "authentication" if exc.code == E_AUTH else ("account" if exc.code in (E_NOT_FOUND, E_PERMISSION)
                                                                 else "request")
            diags.append(Diagnostic(step, False, exc.message, exc.code))
            return ConnectionTestResult(False, diags, exc.code, exc.message)

    def discover_capabilities(self) -> list[CapabilityResult]:
        results = {r.capability: r for r in super().discover_capabilities()}
        listing = results.get(Capability.FILE_LISTING)
        if listing is not None and listing.status == AVAILABLE:
            listing.detail = f"Fileman::list_files permitted through WHM uapi_cpanel as {self.cpanel_user}."
        results[Capability.HOSTING_MALWARE_SCAN] = CapabilityResult(
            Capability.HOSTING_MALWARE_SCAN, UNTESTED,
            "Server-side scanners (ImunifyAV/Imunify360, ClamAV) are not queried through WHM in this release.",
        )
        results[Capability.PROVIDER_SECURITY_API] = CapabilityResult(
            Capability.PROVIDER_SECURITY_API, UNSUPPORTED, "Not implemented for WHM in this release.")
        return list(results.values())

    def open_file_source(self, root: str) -> CPanelFileSource:
        return CPanelFileSource(root, self._client(keep_alive=True))

"""WHM connector against a simulated WHM API 1: account check, uapi_cpanel file access as the chosen account,
the function allow-list, ownership errors, and creation through the API (one WHM login, many accounts)."""

from __future__ import annotations

import hashlib

import httpx
import pytest

from app.connectors.base import ConnectionParams, ConnectorError, SecretMaterial
from app.connectors.whm import WHMClient, WHMConnector
from app.core.http import set_transport_factory
from app.monitoring.inventory import walk_inventory
from tests.conftest import run_dispatched
from tests.test_services import LIMITS, cpanel_env  # noqa: F401 - fixture

ACCOUNTS = {"acme": {"owner": "reseller1", "domain": "acme.example.com", "suspended": 0},
            "other": {"owner": "someone-else", "domain": "other.example.com", "suspended": 0}}


def _whm_transport(files: dict[str, bytes], token="WHMTOKEN", seen=None):
    def ok(data):
        return httpx.Response(200, json={"metadata": {"result": 1, "reason": "OK", "version": 1}, "data": data})

    def fail(reason):
        return httpx.Response(200, json={"metadata": {"result": 0, "reason": reason, "version": 1}})

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.headers.get("authorization") != f"whm reseller1:{token}":
            return httpx.Response(403, text="Access denied")
        q = dict(request.url.params)
        if q.get("api.version") != "1":
            return fail("api.version=1 required")
        fn = request.url.path.rsplit("/", 1)[-1]
        if fn == "accountsummary":
            acct = ACCOUNTS.get(q.get("user", ""))
            if acct is None:
                return fail(f"Account “{q.get('user')}” does not exist.")
            if acct["owner"] != "reseller1":
                return fail("You do not have access to this account.")
            return ok({"acct": [{"user": q["user"], **acct}]})
        if fn != "uapi_cpanel":
            return httpx.Response(404)
        user = q.get("cpanel.user")
        if ACCOUNTS.get(user, {}).get("owner") != "reseller1":
            return fail(f"You do not have access to the account “{user}”.")
        func = f"{q.get('cpanel.module')}::{q.get('cpanel.function')}"
        if func == "Fileman::list_files":
            d = q["dir"].strip("/")
            items, names = [], set()
            for p, data in files.items():
                if not p.startswith(d + "/"):
                    continue
                rest = p[len(d) + 1:]
                name = rest.split("/")[0]
                if name in names:
                    continue
                names.add(name)
                items.append({"file": name, "fullpath": f"/home/{user}/{d}/{name}",
                              "type": "dir" if "/" in rest else "file", "size": str(len(data)),
                              "mtime": "1760000000", "nicemode": "0644"})
            return ok({"uapi": {"status": 1, "errors": None, "data": items}})
        if func == "Fileman::get_file_content":
            p = f"{q['dir'].strip('/')}/{q['file']}"
            return ok({"uapi": {"status": 1, "errors": None, "data": {"content": files[p].decode("latin-1")}}})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


FILES = {"public_html/index.php": b"<?php echo 1;", "public_html/.htaccess": b"Deny from all",
         "public_html/img/a.bin": bytes(range(256))}


def _conn(user="acme", token="WHMTOKEN"):
    return WHMConnector(ConnectionParams("whm_api", "server.acme-hosting.com", 2087, "reseller1", "/public_html",
                                         options={"cpanel_user": user}), SecretMaterial("api_token", token))


def test_whm_reads_files_as_the_chosen_account(cpanel_env):  # noqa: F811
    seen: list = []
    set_transport_factory(lambda: _whm_transport(FILES, seen=seen))
    conn = _conn()
    result = conn.test_connection()
    assert result.ok, result.diagnostics
    assert any("acme.example.com" in d.message for d in result.diagnostics)
    caps = {c.capability.value: c for c in conn.discover_capabilities()}
    assert caps["file_listing"].status == "available" and "as acme" in caps["file_listing"].detail
    assert caps["file_hashing"].status == "available"
    with conn.open_file_source("/public_html") as src:
        res = walk_inventory(src, [], LIMITS)
    assert res.entries["img/a.bin"].sha256 == hashlib.sha256(bytes(range(256))).hexdigest()
    assert ".htaccess" in res.entries
    # Only allow-listed functions, always as the configured account, always to the pinned address.
    for r in seen:
        fn = r.url.path.rsplit("/", 1)[-1]
        q = dict(r.url.params)
        assert fn in ("accountsummary", "uapi_cpanel")
        if fn == "uapi_cpanel":
            assert q["cpanel.user"] == "acme"
            assert (q["cpanel.module"], q["cpanel.function"]) in (("Fileman", "list_files"),
                                                                  ("Fileman", "get_file_content"))
        assert r.url.host == "93.184.216.34" and r.url.port == 2087


def test_whm_reports_missing_and_foreign_accounts_and_bad_tokens(cpanel_env):  # noqa: F811
    set_transport_factory(lambda: _whm_transport(FILES))
    missing = _conn("nobody").test_connection()
    assert not missing.ok and missing.error_code == "not_found" and "does not exist" in missing.error_message
    foreign = _conn("other").test_connection()
    assert not foreign.ok and foreign.error_code == "permission_denied"
    bad = _conn(token="WRONG").test_connection()
    assert not bad.ok and bad.error_code == "auth_failed"


def test_whm_function_allow_list_and_account_name_validation(cpanel_env):  # noqa: F811
    set_transport_factory(lambda: _whm_transport(FILES))
    client = WHMClient(_conn().params, "WHMTOKEN", "acme")
    for fn in ("createacct", "removeacct", "passwd", "uapi_cpanel"):
        with pytest.raises(ConnectorError):
            client.whm_call(fn, {})
    for module, function in (("Fileman", "save_file_content"), ("Fileman", "delete_files"), ("Mysql", "list_databases")):
        with pytest.raises(ConnectorError):
            client.call(module, function, {})
    for bad in ("", "Acme", "acme;rm", "../root", "a" * 40):
        with pytest.raises(ConnectorError):
            WHMClient(_conn().params, "WHMTOKEN", bad)


def test_one_whm_login_can_monitor_several_accounts_through_the_api(alice, cpanel_env, monkeypatch):  # noqa: F811
    from app.core.config import get_settings

    sess, tid = alice
    monkeypatch.setitem(ACCOUNTS, "beta", {"owner": "reseller1", "domain": "beta.example.com", "suspended": 1})
    set_transport_factory(lambda: _whm_transport(FILES))
    assert get_settings().allowed_whm_ports == [2087]

    def create(user):
        return sess.post(f"/api/v1/tenants/{tid}/hosting-accounts", json={
            "name": f"WHM {user}", "connector_type": "whm_api", "hostname": "server.acme-hosting.com",
            "username": "reseller1", "cpanel_user": user, "credential": {"kind": "api_token", "value": "WHMTOKEN"}})

    r = create("acme")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["port"] == 2087 and body["root_path"] == "/public_html" and body["cpanel_user"] == "acme"
    assert run_dispatched() == ["succeeded"]
    assert create("acme").status_code == 409, "the same account twice is a duplicate"
    r = create("beta")
    assert r.status_code == 201, "a second account under the same WHM login is allowed"
    run_dispatched()
    job = sess.get(f"/api/v1/tenants/{tid}/hosting-accounts/{r.json()['id']}").json()["last_test_job"]
    assert "SUSPENDED" in str(job["result"])
    assert create("Bad Name").status_code == 422
    assert "WHMTOKEN" not in str(sess.get(f"/api/v1/tenants/{tid}/hosting-accounts").json())

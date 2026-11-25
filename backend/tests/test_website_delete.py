"""A website with scans, incidents, a service request, file fixes and an investigation can be removed."""

from __future__ import annotations

from tests.test_remediation import _act, _cands, hacked, wporg_files  # noqa: F401 - fixtures
from tests.test_vendor import wp_site  # noqa: F401 - fixture


def test_website_with_full_history_can_be_removed(hacked):  # noqa: F811
    h = hacked
    planted = _cands(h)["wp-includes/class-wp-cache-helper.php"]
    assert _act(h, "quarantine", planted["path"], planted["sha256"]).status_code == 200
    sess, tid, wid = h["sess"], h["tid"], h["wid"]
    r = sess.delete(f"/api/v1/tenants/{tid}/websites/{wid}")
    assert r.status_code == 200, r.text
    assert sess.get(f"/api/v1/tenants/{tid}/websites/{wid}").status_code == 404
    # The request and its record of changes stay (the customer's history with Trust Data).
    t = sess.get(f"/api/v1/tenants/{tid}/tickets/{h['ticket']}")
    assert t.status_code == 200

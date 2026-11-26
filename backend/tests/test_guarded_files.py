"""PHP data files guarded by an unconditional exit (plugin logs in uploads) are not reported as scripts;
anything that could run still is."""

from __future__ import annotations

from app.monitoring.guarded import GuardObserver, is_guarded_php
from tests.test_monitoring_flow import _connect, _scan, _website

MC4WP_LOG = b"<?php exit; ?>\n[2026-11-24 09:09:48] WARNING: Form 123 > Mailchimp API error: 400 Bad Request\n"


def test_guard_recognition_is_strict():
    for ok in (MC4WP_LOG, b"<?php exit(); ?>log", b"<?PHP DIE;", b"\xef\xbb\xbf<?php die('Access denied'); ?>",
               b"<?php exit('Access denied'); __halt_compiler(); ?>data", b'<?php\n  exit("No direct access") ?>x',
               b"<?php exit ?>\n<?php system($_GET['c']); // never reached"):
        assert is_guarded_php(ok), ok
    for bad in (b"<?php system($_GET['c']); exit; ?>",            # code before the guard
                b" <?php exit; ?>",                                 # output before PHP: not the first statement
                b"<?php if (!defined('ABSPATH')) exit; eval($x);",  # conditional guard
                b"<?php exit(system($_GET['c']));",                 # the "message" runs code
                b"<?php exit(\"$x\");",                             # interpolation
                b"<?php exit(\"{${system('id')}}\");",              # complex interpolation
                b"<?php exit('a' . shell_exec('id'));",             # expression, not a literal
                b"<?php exit_handler(); eval($_POST['x']);",        # not the exit keyword
                b"<?= 'x'; exit; ?>", b"<?php\n// exit;\neval($_POST[1]);", b""):
        assert not is_guarded_php(bad), bad
    obs = GuardObserver()
    assert obs.wants("wp-content/uploads/mailchimp-for-wp/debug-log.php")
    assert not obs.wants("wp-content/plugins/x/x.php") and not obs.wants("wp-content/uploads/a.jpg")


def test_plugin_log_in_uploads_is_not_an_incident_but_a_shell_still_is(alice, sftp_server, sftp_root):
    sess, tid = alice
    wid = _website(sess, tid, _connect(sess, tid, sftp_server))
    log_dir = sftp_root / "public_html" / "wp-content" / "uploads" / "mailchimp-for-wp"
    log_dir.mkdir()
    log = log_dir / "debug-log.php"
    log.write_bytes(MC4WP_LOG)
    assert _scan(sess, tid, wid) == ["succeeded"]

    log.write_bytes(MC4WP_LOG + b"[2026-11-24 10:10:00] WARNING: another line\n")  # the plugin writes a line
    disguised = log_dir / "debug-log2.php"
    disguised.write_bytes(b"<?php eval($_POST['x']); exit; ?>\n[2026-11-24] log")  # shell posing as a log
    assert _scan(sess, tid, wid) == ["succeeded"]

    changes = {c["path"]: c for c in sess.get(f"/api/v1/tenants/{tid}/changes",
                                              params={"website_id": wid, "page_size": 100}).json()["items"]}
    logc = changes["wp-content/uploads/mailchimp-for-wp/debug-log.php"]
    assert logc["flags"] == ["guarded_data_file"] and logc["severity"] == "low"
    shell = changes["wp-content/uploads/mailchimp-for-wp/debug-log2.php"]
    assert "script_in_upload_dir" in shell["flags"] and shell["severity"] == "high"
    titles = [i["title"] for i in sess.get(f"/api/v1/tenants/{tid}/incidents").json()["items"]]
    assert not any("debug-log.php" in t for t in titles), titles
    assert any("debug-log2.php" in t for t in titles), titles

    # Removing the guard from the log turns it back into a script.
    log.write_bytes(b"<?php system($_GET['c']); ?>\n" + MC4WP_LOG)
    assert _scan(sess, tid, wid) == ["succeeded"]
    titles = [i["title"] for i in sess.get(f"/api/v1/tenants/{tid}/incidents").json()["items"]]
    assert any(t.endswith("debug-log.php") for t in titles), titles

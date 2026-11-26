"""Access-log parsing and attack detection rules (unit level)."""

from __future__ import annotations

from app.monitoring import logs

A = '203.0.113.9 - - [22/Nov/2026:10:00:{s:02d} +0100] "{m} {p} HTTP/1.1" {st} {sz} "-" "Mozilla/5.0"'


def line(m="GET", p="/", st=200, sz=512, ip="203.0.113.9", s=0):
    return A.format(m=m, p=p, st=st, sz=sz, s=s).replace("203.0.113.9", ip, 1)


def test_parses_combined_common_and_vhost_formats():
    e = logs.parse_line(line(p="/wp-login.php?redirect_to=%2Fwp-admin"))
    assert (e.ip, e.method, e.path, e.query, e.status, e.size) == ("203.0.113.9", "GET", "/wp-login.php",
                                                                 "redirect_to=%2Fwp-admin", 200, 512)
    assert e.at.isoformat() == "2026-11-22T10:00:00+01:00" and e.agent == "Mozilla/5.0"
    common = logs.parse_line('2001:db8::7 - - [22/Nov/2026:10:00:00 +0000] "POST /xmlrpc.php HTTP/1.0" 200 -')
    assert common.ip == "2001:db8::7" and common.size == 0 and common.agent == ""
    vhost = logs.parse_line('www.example.com:443 198.51.100.2 - - [22/Nov/2026:10:00:00 +0000] "GET / HTTP/2.0" 301 0 "-" "x"')
    assert vhost.ip == "198.51.100.2" and vhost.status == 301
    entries, bad = logs.parse("garbage line\n\n" + line() + "\n")
    assert len(entries) == 1 and bad == 1


def test_flagged_file_use_is_critical_for_confirmed_malware():
    ctx = logs.Context(flagged={"/wp-content/uploads/x.php": "ClamAV: Php.Webshell", "/wp-includes/y.php": "not in release"},
                       critical={"/wp-content/uploads/x.php"})
    entries, _ = logs.parse("\n".join([
        line("POST", "/wp-content/uploads/x.php", 200),
        line("GET", "/wp-includes/y.php", 200, ip="198.51.100.4"),
        line("GET", "/wp-includes/y.php", 404, ip="198.51.100.5"),
    ]))
    found = {f.rule + ":" + f.paths[0]: f for f in logs.analyse(entries, ctx)[0]}
    assert found["flagged_file_accessed:/wp-content/uploads/x.php"].severity == "critical"
    assert found["flagged_file_accessed:/wp-includes/y.php"].ips == ["198.51.100.4"], "404s do not count"
    assert "php_upload_executed:/wp-content/uploads/x.php" not in found, "reported once, as the stronger finding"


def test_php_post_in_uploads_and_exposed_secrets():
    entries, _ = logs.parse("\n".join([
        line("POST", "/wp-content/uploads/2026/11/cache.php", 200),
        line("GET", "/wp-content/uploads/photo.jpg", 200),
        line("GET", "/.env", 200, 1200),
        line("GET", "/.git/config", 404, 0),
        line("GET", "/wp-config.php.bak", 200, 0),
        line("GET", "/backup.sql", 200, 90000),
    ]))
    findings, stats = logs.analyse(entries, logs.Context())
    rules = sorted((f.rule, f.paths[0]) for f in findings)
    assert rules == [("php_upload_executed", "/wp-content/uploads/2026/11/cache.php"),
                     ("sensitive_file_exposed", "/.env"), ("sensitive_file_exposed", "/backup.sql")]
    assert stats["probes_for_sensitive_files"] == 1


def test_bruteforce_and_probable_success():
    lines = [line("POST", "/wp-login.php", 200, ip="192.0.2.50", s=i % 60) for i in range(25)]
    lines += [line("POST", "/wp-login.php", 302, ip="192.0.2.50")]
    lines += [line("POST", "/xmlrpc.php", 200, ip="192.0.2.77") for _ in range(30)]
    lines += [line("POST", "/wp-login.php", 200, ip="192.0.2.99") for _ in range(5)]  # below threshold
    lines += [line("POST", "/wp-login.php", 302, ip="192.0.2.99")]  # an ordinary login
    findings, stats = logs.analyse(logs.parse("\n".join(lines))[0], logs.Context())
    by_rule = {f.rule: f for f in findings}
    assert by_rule["login_bruteforce_success"].ips == ["192.0.2.50"]
    assert set(by_rule["login_bruteforce"].ips) == {"192.0.2.50", "192.0.2.77"}
    assert "192.0.2.99" not in by_rule["login_bruteforce"].ips
    assert stats["top_addresses"][0] == {"ip": "192.0.2.77", "requests": 30}


def test_quiet_log_raises_nothing():
    entries, _ = logs.parse("\n".join(line("GET", f"/page-{i}", 200, ip=f"198.51.100.{i}") for i in range(50)))
    assert logs.analyse(entries, logs.Context())[0] == []

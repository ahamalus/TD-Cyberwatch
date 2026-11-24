"""Recognise PHP data files that cannot run: the first statement is an unconditional ``exit``/``die``.

Plugins keep logs and caches as ``.php`` files in ``wp-content/uploads`` on purpose: a ``.txt`` or ``.log``
there would be readable by anyone who guesses the URL, whereas ``<?php exit; ?>`` on the first line makes the
web server stop before sending anything. Examples: Mailchimp for WordPress (``mailchimp-for-wp/debug-log.php``),
Wordfence (``<?php exit('Access denied'); __halt_compiler(); ?>``). These files change every time the plugin
writes a line, so "script added or modified in an upload folder" would fire on every scan.

The check is strict and content-based (never by file name): the file must start, after an optional UTF-8
BOM, with ``<?php`` and then immediately ``exit`` or ``die``, with at most a plain string literal as the
message (no variables, escapes or interpolation), ending the statement. PHP executes nothing after that, so
the rest of the file is data. If the guard is removed or changed, the file is flagged as before. Malware
scanning of its content is unaffected.
"""

from __future__ import annotations

import posixpath
import re
import threading

from app.monitoring.inventory import matches_any
from app.monitoring.rules import UPLOAD_DIR_PATTERNS

PHP_EXTENSIONS = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht", ".phar"}
_GUARD = re.compile(
    rb"\A(?:\xef\xbb\xbf)?<\?php\s+(?:exit|die)\s*"
    rb"(?:\(\s*(?:'[^'\\$]*'|\"[^\"\\${}]*\")?\s*\))?\s*(?:;|\?>)",
    re.IGNORECASE,
)


def is_guarded_php(data: bytes) -> bool:
    return bool(_GUARD.match(data[:4096]))


class GuardObserver:
    """ContentObserver: notes which PHP files in upload folders are guarded data files (thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.guarded: set[str] = set()

    def wants(self, path: str) -> bool:
        return posixpath.splitext(path)[1].lower() in PHP_EXTENSIONS and matches_any(path, UPLOAD_DIR_PATTERNS)

    def observe(self, path: str, data: bytes) -> None:
        if is_guarded_php(data):
            with self._lock:
                self.guarded.add(path)


class CompositeObserver:
    """Several ContentObservers over one walk; each sees only the files it asked for."""

    def __init__(self, *observers) -> None:
        self.observers = observers

    def wants(self, path: str) -> bool:
        return any(o.wants(path) for o in self.observers)

    def observe(self, path: str, data: bytes) -> None:
        for o in self.observers:
            if o.wants(path):
                o.observe(path, data)
